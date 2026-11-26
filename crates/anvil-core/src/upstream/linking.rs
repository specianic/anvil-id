//! Account-linking decision for an upstream login (AUTH-11).
//!
//! Rules (research provider matrix, "account linking"):
//! - An existing `(connection, subject)` link always wins over any email match: active user ->
//!   sign in, inactive user -> refuse.
//! - Auto-link only when the upstream email is verified AND trusted (already folded into
//!   [`UpstreamIdentity::email_verified`]), the matching local account's email is verified,
//!   auto-linking is enabled for the tenant, and the connection is not Microsoft (whose addresses
//!   are tenant-admin controlled).
//! - Any other email match needs confirmation by signing in to the existing account
//!   ([`LinkDecision::PendingLink`]); the candidate account is revealed only when the upstream
//!   email is verified and trusted (no account enumeration through unverified addresses).
//! - No match: just-in-time registration when allowed ([`jit_allowed`]), else refuse.
//!
//! Enterprise connections (owned by an organization, ORG-03) decide the upstream email's trust
//! with [`enterprise_email_trust`] before [`link_decision`]: only an address on one of the org's
//! **verified** domains can be trusted, so a customer's IdP cannot assert addresses at someone
//! else's domain (cross-org account takeover).
//!
//! Pure: no I/O.

use super::claims::UpstreamIdentity;
use crate::model::{
    ConnectionKind, IdentityLink, RegistrationMode, TenantSettings, UserId, normalize_email,
};

/// Whether an upstream login without a linked or matching account may create one just in time.
///
/// - An organization-owned connection whose asserted email is trusted for that org
///   (`org_trusted_email`: the [`enterprise_email_trust`] result, i.e. on one of the org's
///   **verified** domains) may create accounts whatever the tenant's registration setting: a
///   tenant or org admin explicitly configured the connection and verified the domain. A closed
///   B2B tenant therefore still onboards the org's own people through their IdP.
/// - Every other case (tenant-level connections, and org connections asserting an email outside
///   the org's verified domains) follows the tenant setting `upstream_registration`, which
///   defaults to "registration mode is `open`" when unset.
pub fn jit_allowed(settings: &TenantSettings, org_trusted_email: bool) -> bool {
    org_trusted_email
        || settings
            .upstream_registration
            .unwrap_or(settings.registration == RegistrationMode::Open)
}

/// Whether the email asserted by an organization's IdP is trusted (research Pattern 9):
///
/// - the email is present and normalises (trimmed, lowercase, one `@`);
/// - its domain is exactly one of `verified_org_domains` (the org's verified domains, lowercase
///   A-labels), compared case-insensitively; a subdomain of a verified domain is not covered,
///   and a non-ASCII (U-label) domain never matches;
/// - `upstream_verified`: OIDC/OAuth passes `Some(identity.email_verified)` (the provider's
///   `email_verified`, strictly boolean `true`, already AND-ed with the connection's trust);
///   SAML passes `None` (the signed assertion vouches, and the verified org domain is what grants
///   trust).
///
/// Anything else is untrusted: never auto-linked, and a match needs the Phase 4 confirmation.
pub fn enterprise_email_trust(
    email: Option<&str>,
    verified_org_domains: &[String],
    upstream_verified: Option<bool>,
) -> bool {
    if upstream_verified == Some(false) {
        return false;
    }
    let Some(email) = email.and_then(|e| normalize_email(e).ok()) else {
        return false;
    };
    let Some((_, domain)) = email.rsplit_once('@') else {
        return false;
    };
    domain.is_ascii()
        && verified_org_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain))
}

/// A local account whose email equals the upstream email.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmailMatch {
    pub user_id: UserId,
    /// The local account's email is verified.
    pub email_verified: bool,
}

/// Inputs of [`link_decision`].
#[derive(Debug, Clone, Copy)]
pub struct LinkInputs<'a> {
    pub identity: &'a UpstreamIdentity,
    /// The link for `(connection, identity.subject)`, if any.
    pub existing_link: Option<&'a IdentityLink>,
    /// The user of `existing_link` is active (ignored without a link).
    pub link_user_active: bool,
    pub email_match: Option<EmailMatch>,
    /// Tenant setting `auto_link`.
    pub auto_link_enabled: bool,
    pub connection_kind: ConnectionKind,
    /// Just-in-time account creation is allowed for this login (see [`jit_allowed`]).
    pub registration_allowed: bool,
}

/// Why an upstream login is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// The linked local account is not active.
    Inactive,
    /// No linked or matching account and registration is not allowed.
    NoAccount,
}

/// What to do with an upstream login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkDecision {
    /// Sign in the already linked user.
    SignIn(UserId),
    /// Create the link to this user and sign in.
    AutoLink(UserId),
    /// The user must sign in to the existing account to confirm the link. `candidate` is set only
    /// when the upstream email is verified and trusted.
    PendingLink {
        candidate: Option<UserId>,
    },
    /// Create a new local user with the link.
    JitCreate {
        email_verified: bool,
    },
    Refuse(RefuseReason),
}

/// Decide how to handle an upstream login.
pub fn link_decision(inputs: &LinkInputs<'_>) -> LinkDecision {
    if let Some(link) = inputs.existing_link {
        return if inputs.link_user_active {
            LinkDecision::SignIn(link.user_id)
        } else {
            LinkDecision::Refuse(RefuseReason::Inactive)
        };
    }
    // Already AND-ed with the connection's trust by the normaliser.
    let upstream_verified = inputs.identity.email_verified;
    if let Some(m) = inputs.email_match {
        let auto = upstream_verified
            && m.email_verified
            && inputs.auto_link_enabled
            && inputs.connection_kind != ConnectionKind::Microsoft;
        return if auto {
            LinkDecision::AutoLink(m.user_id)
        } else {
            LinkDecision::PendingLink {
                candidate: upstream_verified.then_some(m.user_id),
            }
        };
    }
    if inputs.registration_allowed {
        LinkDecision::JitCreate {
            email_verified: upstream_verified,
        }
    } else {
        LinkDecision::Refuse(RefuseReason::NoAccount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConnectionId, IdentityLinkId, TenantId};
    use proptest::prelude::*;
    use serde_json::Map;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn uid(n: u128) -> UserId {
        UserId(Uuid::from_u128(n))
    }

    fn identity(email_verified: bool) -> UpstreamIdentity {
        UpstreamIdentity {
            subject: "sub-1".into(),
            email: Some("a@b.example".into()),
            email_verified,
            given_name: None,
            family_name: None,
            name: None,
            metadata: Map::new(),
        }
    }

    fn link(user: UserId) -> IdentityLink {
        IdentityLink {
            id: IdentityLinkId::new_v7(),
            tenant_id: TenantId::new_v7(),
            user_id: user,
            connection_id: ConnectionId::new_v7(),
            subject: "sub-1".into(),
            email_at_link: None,
            metadata: Map::new(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            last_used_at: None,
        }
    }

    fn inputs<'a>(id: &'a UpstreamIdentity) -> LinkInputs<'a> {
        LinkInputs {
            identity: id,
            existing_link: None,
            link_user_active: false,
            email_match: None,
            auto_link_enabled: true,
            connection_kind: ConnectionKind::Google,
            registration_allowed: true,
        }
    }

    fn matched(n: u128, verified: bool) -> Option<EmailMatch> {
        Some(EmailMatch {
            user_id: uid(n),
            email_verified: verified,
        })
    }

    #[test]
    fn existing_active_link_signs_in_ignoring_email() {
        let id = identity(true);
        let l = link(uid(1));
        let mut i = inputs(&id);
        i.existing_link = Some(&l);
        i.link_user_active = true;
        i.email_match = matched(2, true);
        assert_eq!(link_decision(&i), LinkDecision::SignIn(uid(1)));
    }

    #[test]
    fn existing_inactive_link_refused() {
        let id = identity(true);
        let l = link(uid(1));
        let mut i = inputs(&id);
        i.existing_link = Some(&l);
        i.link_user_active = false;
        i.email_match = matched(2, true);
        assert_eq!(
            link_decision(&i),
            LinkDecision::Refuse(RefuseReason::Inactive)
        );
    }

    #[test]
    fn verified_trusted_match_auto_links() {
        let id = identity(true);
        let mut i = inputs(&id);
        i.email_match = matched(2, true);
        assert_eq!(link_decision(&i), LinkDecision::AutoLink(uid(2)));
    }

    #[test]
    fn unverified_upstream_email_never_links_and_hides_candidate() {
        let id = identity(false);
        let mut i = inputs(&id);
        i.email_match = matched(2, true);
        assert_eq!(
            link_decision(&i),
            LinkDecision::PendingLink { candidate: None }
        );
    }

    #[test]
    fn unverified_local_email_refuses_auto_link() {
        let id = identity(true);
        let mut i = inputs(&id);
        i.email_match = matched(2, false);
        assert_eq!(
            link_decision(&i),
            LinkDecision::PendingLink {
                candidate: Some(uid(2))
            }
        );
    }

    #[test]
    fn auto_link_disabled_needs_confirmation() {
        let id = identity(true);
        let mut i = inputs(&id);
        i.email_match = matched(2, true);
        i.auto_link_enabled = false;
        assert_eq!(
            link_decision(&i),
            LinkDecision::PendingLink {
                candidate: Some(uid(2))
            }
        );
    }

    #[test]
    fn microsoft_never_auto_links() {
        // Even if a caller forgot to clear email_verified for Microsoft.
        let id = identity(true);
        let mut i = inputs(&id);
        i.email_match = matched(2, true);
        i.connection_kind = ConnectionKind::Microsoft;
        assert_eq!(
            link_decision(&i),
            LinkDecision::PendingLink {
                candidate: Some(uid(2))
            }
        );
    }

    #[test]
    fn other_kinds_auto_link() {
        for kind in [
            ConnectionKind::Google,
            ConnectionKind::Apple,
            ConnectionKind::Github,
            ConnectionKind::Oidc,
            ConnectionKind::Oauth2,
        ] {
            let id = identity(true);
            let mut i = inputs(&id);
            i.email_match = matched(3, true);
            i.connection_kind = kind;
            assert_eq!(
                link_decision(&i),
                LinkDecision::AutoLink(uid(3)),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn no_match_jit_create_or_refuse() {
        for ev in [true, false] {
            let id = identity(ev);
            let i = inputs(&id);
            assert_eq!(
                link_decision(&i),
                LinkDecision::JitCreate { email_verified: ev }
            );
            let mut i = inputs(&id);
            i.registration_allowed = false;
            assert_eq!(
                link_decision(&i),
                LinkDecision::Refuse(RefuseReason::NoAccount)
            );
        }
    }

    fn domains(list: &[&str]) -> Vec<String> {
        list.iter().map(|d| (*d).to_owned()).collect()
    }

    #[test]
    fn enterprise_trust_needs_a_verified_org_domain_and_upstream_verification() {
        let acme = domains(&["acme.com"]);
        assert!(enterprise_email_trust(
            Some("a@acme.com"),
            &acme,
            Some(true)
        ));
        assert!(!enterprise_email_trust(
            Some("a@acme.com"),
            &acme,
            Some(false)
        ));
    }

    #[test]
    fn enterprise_trust_refuses_other_and_sub_domains() {
        let acme = domains(&["acme.com"]);
        for email in [
            "a@sub.acme.com",
            "a@acme.com.evil.example",
            "a@evilacme.com",
            "a@orgb.example",
            "a@acme.co",
        ] {
            assert!(
                !enterprise_email_trust(Some(email), &acme, Some(true)),
                "{email}"
            );
        }
        assert!(!enterprise_email_trust(Some("a@acme.com"), &[], Some(true)));
    }

    #[test]
    fn enterprise_trust_compares_domains_case_insensitively_after_normalisation() {
        let acme = domains(&["acme.com"]);
        assert!(enterprise_email_trust(
            Some("  Alice@ACME.Com "),
            &acme,
            Some(true)
        ));
        let upper = domains(&["ACME.COM"]);
        assert!(enterprise_email_trust(
            Some("a@acme.com"),
            &upper,
            Some(true)
        ));
    }

    #[test]
    fn enterprise_trust_refuses_missing_or_malformed_email() {
        let acme = domains(&["acme.com"]);
        assert!(!enterprise_email_trust(None, &acme, Some(true)));
        assert!(!enterprise_email_trust(None, &acme, None));
        for email in ["", "acme.com", "a@b@acme.com", "a b@acme.com", "@acme.com"] {
            assert!(
                !enterprise_email_trust(Some(email), &acme, Some(true)),
                "{email:?}"
            );
        }
        // A U-label never matches the stored A-label (and is never trusted on its own).
        let idn = domains(&["xn--bcher-kva.example"]);
        assert!(!enterprise_email_trust(
            Some("a@bücher.example"),
            &idn,
            Some(true)
        ));
    }

    #[test]
    fn enterprise_trust_saml_variant_relies_on_the_verified_domain_only() {
        let acme = domains(&["acme.com", "acme.io"]);
        assert!(enterprise_email_trust(Some("a@acme.io"), &acme, None));
        assert!(!enterprise_email_trust(Some("a@orgb.example"), &acme, None));
        assert!(!enterprise_email_trust(Some("a@sub.acme.io"), &acme, None));
    }

    proptest! {
        #[test]
        fn enterprise_trust_implies_listed_domain(
            local in "[a-z]{1,8}",
            domain in "[a-z]{1,6}\\.(com|example|io)",
            listed in proptest::collection::vec("[a-z]{1,6}\\.(com|example|io)", 0..4),
            upstream in proptest::option::of(any::<bool>()),
        ) {
            let email = format!("{local}@{domain}");
            let trusted = enterprise_email_trust(Some(&email), &listed, upstream);
            prop_assert_eq!(
                trusted,
                upstream != Some(false) && listed.iter().any(|d| d == &domain)
            );
        }
    }

    #[test]
    fn match_with_registration_disabled_still_pending() {
        let id = identity(false);
        let mut i = inputs(&id);
        i.email_match = matched(2, true);
        i.registration_allowed = false;
        assert_eq!(
            link_decision(&i),
            LinkDecision::PendingLink { candidate: None }
        );
    }

    fn kind_strategy() -> impl Strategy<Value = ConnectionKind> {
        prop::sample::select(ConnectionKind::ALL.to_vec())
    }

    prop_compose! {
        fn any_inputs()(
            ev in any::<bool>(),
            has_link in any::<bool>(),
            link_user in any::<u128>(),
            active in any::<bool>(),
            m in proptest::option::of((any::<u128>(), any::<bool>())),
            auto in any::<bool>(),
            kind in kind_strategy(),
            reg in any::<bool>(),
        ) -> (bool, Option<u128>, bool, Option<(u128, bool)>, bool, ConnectionKind, bool) {
            (ev, has_link.then_some(link_user), active, m, auto, kind, reg)
        }
    }

    proptest! {
        #[test]
        fn decision_invariants(
            (ev, link_user, active, m, auto, kind, reg) in any_inputs()
        ) {
            let id = identity(ev);
            let l = link_user.map(|n| link(uid(n)));
            let i = LinkInputs {
                identity: &id,
                existing_link: l.as_ref(),
                link_user_active: active,
                email_match: m.map(|(n, v)| EmailMatch { user_id: uid(n), email_verified: v }),
                auto_link_enabled: auto,
                connection_kind: kind,
                registration_allowed: reg,
            };
            let d = link_decision(&i);
            if !ev {
                let revealed = matches!(d, LinkDecision::PendingLink { candidate: Some(_) });
                prop_assert!(!matches!(d, LinkDecision::AutoLink(_)));
                prop_assert!(!revealed, "candidate hidden for unverified email");
            }
            if kind == ConnectionKind::Microsoft {
                prop_assert!(!matches!(d, LinkDecision::AutoLink(_)));
            }
            if let Some(n) = link_user {
                if active {
                    prop_assert_eq!(d, LinkDecision::SignIn(uid(n)));
                } else {
                    prop_assert_eq!(d, LinkDecision::Refuse(RefuseReason::Inactive));
                }
            }
            if let LinkDecision::AutoLink(u) = d {
                let (n, v) = m.unwrap();
                prop_assert_eq!(u, uid(n));
                prop_assert!(v, "never auto-link to an unverified local email");
                prop_assert!(auto);
            }
        }
    }

    fn settings(
        registration: RegistrationMode,
        upstream_registration: Option<bool>,
    ) -> TenantSettings {
        TenantSettings {
            registration,
            upstream_registration,
            ..TenantSettings::default()
        }
    }

    const MODES: [RegistrationMode; 3] = [
        RegistrationMode::Open,
        RegistrationMode::InviteOnly,
        RegistrationMode::Disabled,
    ];
    const UPSTREAM: [Option<bool>; 3] = [None, Some(true), Some(false)];

    /// The tenant rule: `upstream_registration`, unset = registration mode `open`.
    fn tenant_rule(mode: RegistrationMode, upstream: Option<bool>) -> bool {
        match upstream {
            Some(v) => v,
            None => mode == RegistrationMode::Open,
        }
    }

    #[test]
    fn jit_allowed_for_org_trusted_email_whatever_the_tenant_setting() {
        for mode in MODES {
            for upstream in UPSTREAM {
                assert!(
                    jit_allowed(&settings(mode, upstream), true),
                    "{mode:?} / {upstream:?}"
                );
            }
        }
    }

    #[test]
    fn jit_follows_the_tenant_rule_without_an_org_trusted_email() {
        // Tenant connections and org connections asserting an email outside the org's verified
        // domains both pass `false`.
        for mode in MODES {
            for upstream in UPSTREAM {
                assert_eq!(
                    jit_allowed(&settings(mode, upstream), false),
                    tenant_rule(mode, upstream),
                    "{mode:?} / {upstream:?}"
                );
            }
        }
        assert!(!jit_allowed(
            &settings(RegistrationMode::Disabled, None),
            false
        ));
        assert!(!jit_allowed(
            &settings(RegistrationMode::Open, Some(false)),
            false
        ));
        assert!(jit_allowed(&settings(RegistrationMode::Open, None), false));
    }
}
