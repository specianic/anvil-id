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
//! - No match: just-in-time registration when allowed, else refuse.
//!
//! Pure: no I/O.

use super::claims::UpstreamIdentity;
use crate::model::{ConnectionKind, IdentityLink, UserId};

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
    /// Tenant setting `upstream_registration` (just-in-time account creation).
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
    PendingLink { candidate: Option<UserId> },
    /// Create a new local user with the link.
    JitCreate { email_verified: bool },
    Refuse(RefuseReason),
}

/// Decide how to handle an upstream login.
pub fn link_decision(inputs: &LinkInputs<'_>) -> LinkDecision {
    let _ = inputs;
    LinkDecision::Refuse(RefuseReason::NoAccount)
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
            assert_eq!(link_decision(&i), LinkDecision::AutoLink(uid(3)), "{kind:?}");
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
}
