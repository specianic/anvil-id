//! The active organization of an authorization, its token claims and the `org:admin` scope
//! bound (ORG-02, decision Q1).
//!
//! Pure functions over model values:
//! - [`resolve_active_org`] decides the org of an authorization from the client's
//!   [`OrgClientPolicy`], the `organization` authorization parameter and the user's
//!   memberships. The result is bound to the grant (code, token family), never to the session.
//! - [`org_claims_json`] produces the org claims of one token from the per-issuance
//!   [`OrgClaims`] and the tenant's claim mapping.
//! - [`bound_org_admin_scope`] removes `org:admin` from a scope unless the user holds the
//!   `org:admin` permission in the active org.

use serde_json::{Map, Value};

use super::claims_mapping::{is_reserved_claim, rule_applies, sorted_unique};
use crate::model::{
    ClaimMappingSettings, ClaimRule, OrgClaims, OrgClientPolicy, Organization, Scope, TokenTarget,
};
use crate::service::admin_scope::ORG_ADMIN_SCOPE;

/// The org of one authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveOrg {
    /// No org: no org claims are issued.
    NoOrg,
    /// This membership is the active org.
    Selected(Organization),
    /// The user belongs to several orgs and none was requested: show the switcher.
    NeedsChoice,
    /// The user is not a member of the requested org, or the client requires an org and the
    /// user has none: `access_denied`.
    Denied,
    /// The client does not use organizations but the request named one: `invalid_request`.
    Refused,
}

/// Whether `requested` names `org`: its canonical (lowercase, hyphenated) UUID or its slug,
/// compared exactly. Display names never match.
fn names(org: &Organization, requested: &str) -> bool {
    org.id.to_string() == requested || org.slug == requested
}

/// Resolves the active org.
///
/// | policy | requested | memberships | result |
/// |---|---|---|---|
/// | `off` | none | any | `NoOrg` |
/// | `off` | some | any | `Refused` |
/// | `optional`/`required` | a membership (id or slug) | | `Selected` |
/// | `optional`/`required` | a non-member org | | `Denied` |
/// | `optional` | none | any | `NoOrg` |
/// | `required` | none | none | `Denied` |
/// | `required` | none | one | `Selected` |
/// | `required` | none | several | `NeedsChoice` |
///
/// An id match wins over a slug match, so a slug that happens to look like another org's id
/// can never shadow that org.
pub fn resolve_active_org(
    policy: OrgClientPolicy,
    requested: Option<&str>,
    memberships: &[Organization],
) -> ActiveOrg {
    match (policy, requested) {
        (OrgClientPolicy::Off, None) => ActiveOrg::NoOrg,
        (OrgClientPolicy::Off, Some(_)) => ActiveOrg::Refused,
        (_, Some(req)) => memberships
            .iter()
            .find(|o| o.id.to_string() == req)
            .or_else(|| memberships.iter().find(|o| names(o, req)))
            .map_or(ActiveOrg::Denied, |o| ActiveOrg::Selected(o.clone())),
        (OrgClientPolicy::Optional, None) => ActiveOrg::NoOrg,
        (OrgClientPolicy::Required, None) => match memberships {
            [] => ActiveOrg::Denied,
            [only] => ActiveOrg::Selected(only.clone()),
            _ => ActiveOrg::NeedsChoice,
        },
    }
}

/// The org claim names AnvilID sets itself; no mapping rule may produce them.
const ORG_ID_CLAIM: &str = "org_id";
const ORG_SLUG_CLAIM: &str = "org_slug";

/// Whether an org rule may emit under its configured name: never `org_id`/`org_slug`, never
/// another reserved claim, except the rule's own default name.
fn org_rule_name_allowed(rule: &ClaimRule, own_name: &str) -> bool {
    let c = rule.claim.as_str();
    !c.is_empty()
        && !c.eq_ignore_ascii_case(ORG_ID_CLAIM)
        && !c.eq_ignore_ascii_case(ORG_SLUG_CLAIM)
        && (c == own_name || !is_reserved_claim(c))
}

/// The org claims of one token. Nothing when there is no active org. Otherwise `org_id` (UUID
/// string) and `org_slug` always, then the `org_roles` and `org_permissions` mapping rules with
/// the same gating as the tenant rules (targets, scope, sorted de-duplicated arrays, omitted
/// when empty).
///
/// [`super::claims_mapping::validate_mapping`] keeps the org rule names disjoint from every
/// other mapped claim; a stored rule that would shadow `org_id`, `org_slug` or another
/// reserved claim is skipped.
pub fn org_claims_json(
    claims: Option<&OrgClaims>,
    settings: &ClaimMappingSettings,
    target: TokenTarget,
    granted: &Scope,
) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(claims) = claims else {
        return out;
    };
    out.insert(
        ORG_ID_CLAIM.to_owned(),
        Value::from(claims.org_id.to_string()),
    );
    out.insert(
        ORG_SLUG_CLAIM.to_owned(),
        Value::from(claims.org_slug.clone()),
    );
    for (rule, own_name, values) in [
        (settings.org_roles.as_ref(), "org_roles", &claims.roles),
        (
            settings.org_permissions.as_ref(),
            "org_permissions",
            &claims.permissions,
        ),
    ] {
        let Some(rule) = rule.filter(|r| rule_applies(r, granted, target)) else {
            continue;
        };
        if !org_rule_name_allowed(rule, own_name) || out.contains_key(&rule.claim) {
            continue;
        }
        if let Some(v) = sorted_unique(values) {
            out.insert(rule.claim.clone(), v);
        }
    }
    out
}

/// Bounds the `org:admin` scope: it stays only when there is an active org and the user's
/// permissions in it include `org:admin`. Every other scope token is untouched.
pub fn bound_org_admin_scope(
    requested: &Scope,
    active_org_permissions: Option<&[String]>,
) -> Scope {
    let allowed = active_org_permissions.is_some_and(|p| p.iter().any(|x| x == ORG_ADMIN_SCOPE));
    requested
        .iter()
        .filter(|s| allowed || *s != ORG_ADMIN_SCOPE)
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::OffsetDateTime;

    use super::*;
    use crate::model::{OrgId, OrgSettings, TenantId};

    fn org(slug: &str) -> Organization {
        Organization {
            id: OrgId::new_v7(),
            tenant_id: TenantId::new_v7(),
            slug: slug.to_owned(),
            display_name: format!("{slug} Inc"),
            mfa_policy: None,
            settings: OrgSettings::default(),
            metadata: json!({}),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    use OrgClientPolicy::{Off, Optional, Required};

    #[test]
    fn off_without_request_has_no_org() {
        assert_eq!(resolve_active_org(Off, None, &[]), ActiveOrg::NoOrg);
        assert_eq!(resolve_active_org(Off, None, &[org("a")]), ActiveOrg::NoOrg);
    }

    #[test]
    fn off_with_request_is_refused() {
        let a = org("a");
        assert_eq!(
            resolve_active_org(Off, Some("a"), std::slice::from_ref(&a)),
            ActiveOrg::Refused
        );
        assert_eq!(resolve_active_org(Off, Some("x"), &[]), ActiveOrg::Refused);
    }

    #[test]
    fn optional_without_request_has_no_org() {
        assert_eq!(resolve_active_org(Optional, None, &[]), ActiveOrg::NoOrg);
        assert_eq!(
            resolve_active_org(Optional, None, &[org("a")]),
            ActiveOrg::NoOrg
        );
        assert_eq!(
            resolve_active_org(Optional, None, &[org("a"), org("b")]),
            ActiveOrg::NoOrg
        );
    }

    #[test]
    fn requested_membership_is_selected_by_id_or_slug() {
        let (a, b) = (org("a"), org("b"));
        let ms = [a.clone(), b.clone()];
        for p in [Optional, Required] {
            assert_eq!(
                resolve_active_org(p, Some("b"), &ms),
                ActiveOrg::Selected(b.clone())
            );
            assert_eq!(
                resolve_active_org(p, Some(&a.id.to_string()), &ms),
                ActiveOrg::Selected(a.clone())
            );
        }
    }

    #[test]
    fn requested_non_member_is_denied() {
        let a = org("a");
        let other = org("other");
        for p in [Optional, Required] {
            assert_eq!(
                resolve_active_org(p, Some("other"), std::slice::from_ref(&a)),
                ActiveOrg::Denied
            );
            assert_eq!(
                resolve_active_org(p, Some(&other.id.to_string()), std::slice::from_ref(&a)),
                ActiveOrg::Denied
            );
            assert_eq!(resolve_active_org(p, Some("a"), &[]), ActiveOrg::Denied);
        }
    }

    #[test]
    fn request_matching_is_exact_and_never_by_display_name() {
        let a = org("acme");
        let ms = [a.clone()];
        for req in [
            "ACME",
            "acme ",
            "acme Inc",
            "",
            &a.id.to_string().to_uppercase(),
        ] {
            assert_eq!(
                resolve_active_org(Required, Some(req), &ms),
                ActiveOrg::Denied,
                "{req:?}"
            );
        }
    }

    #[test]
    fn id_match_wins_over_a_lookalike_slug() {
        let target = org("target");
        let mut squatter = org("x");
        squatter.slug = target.id.to_string();
        let ms = [squatter.clone(), target.clone()];
        assert_eq!(
            resolve_active_org(Required, Some(&target.id.to_string()), &ms),
            ActiveOrg::Selected(target)
        );
    }

    #[test]
    fn required_without_request() {
        let (a, b) = (org("a"), org("b"));
        assert_eq!(resolve_active_org(Required, None, &[]), ActiveOrg::Denied);
        assert_eq!(
            resolve_active_org(Required, None, std::slice::from_ref(&a)),
            ActiveOrg::Selected(a.clone())
        );
        assert_eq!(
            resolve_active_org(Required, None, &[a, b]),
            ActiveOrg::NeedsChoice
        );
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    fn claims() -> OrgClaims {
        OrgClaims {
            org_id: OrgId::new_v7(),
            org_slug: "acme".into(),
            roles: strings(&["b", "a", "b"]),
            permissions: strings(&["y", "x"]),
        }
    }

    fn scope(s: &str) -> Scope {
        Scope::parse(s).unwrap()
    }

    #[test]
    fn no_org_emits_nothing() {
        let s = ClaimMappingSettings::default();
        for t in TokenTarget::ALL {
            assert!(org_claims_json(None, &s, *t, &scope("openid roles")).is_empty());
        }
    }

    #[test]
    fn id_and_slug_are_always_emitted() {
        let c = claims();
        let none = ClaimMappingSettings {
            roles: None,
            permissions: None,
            org_roles: None,
            org_permissions: None,
        };
        for t in TokenTarget::ALL {
            let m = org_claims_json(Some(&c), &none, *t, &scope("openid"));
            assert_eq!(m.get("org_id"), Some(&json!(c.org_id.to_string())), "{t:?}");
            assert_eq!(m.get("org_slug"), Some(&json!("acme")), "{t:?}");
            assert_eq!(m.len(), 2);
        }
    }

    #[test]
    fn default_org_roles_are_gated_by_the_roles_scope() {
        let c = claims();
        let s = ClaimMappingSettings::default();
        for t in TokenTarget::ALL {
            let m = org_claims_json(Some(&c), &s, *t, &scope("openid"));
            assert!(!m.contains_key("org_roles"), "{t:?}");
            let m = org_claims_json(Some(&c), &s, *t, &scope("openid roles"));
            assert_eq!(m.get("org_roles"), Some(&json!(["a", "b"])), "{t:?}");
        }
    }

    #[test]
    fn default_org_permissions_go_to_the_access_token_only() {
        let c = claims();
        let s = ClaimMappingSettings::default();
        let at = org_claims_json(Some(&c), &s, TokenTarget::AccessToken, &scope("openid"));
        assert_eq!(at.get("org_permissions"), Some(&json!(["x", "y"])));
        for t in [TokenTarget::IdToken, TokenTarget::Userinfo] {
            let m = org_claims_json(Some(&c), &s, t, &scope("openid roles"));
            assert!(!m.contains_key("org_permissions"), "{t:?}");
        }
    }

    #[test]
    fn empty_org_roles_are_omitted() {
        let c = OrgClaims {
            roles: vec![],
            permissions: vec![],
            ..claims()
        };
        let m = org_claims_json(
            Some(&c),
            &ClaimMappingSettings::default(),
            TokenTarget::AccessToken,
            &scope("openid roles"),
        );
        assert!(!m.contains_key("org_roles"));
        assert!(!m.contains_key("org_permissions"));
    }

    #[test]
    fn renamed_org_rules_are_used_but_never_shadow_reserved_claims() {
        let c = claims();
        let rule = |claim: &str| ClaimRule {
            claim: claim.to_owned(),
            tokens: vec![TokenTarget::AccessToken],
            scope: None,
        };
        let renamed = ClaimMappingSettings {
            org_roles: Some(rule("tenant_roles")),
            ..ClaimMappingSettings::default()
        };
        let m = org_claims_json(
            Some(&c),
            &renamed,
            TokenTarget::AccessToken,
            &scope("openid"),
        );
        assert_eq!(m.get("tenant_roles"), Some(&json!(["a", "b"])));

        for bad in ["org_id", "ORG_SLUG", "sub", "org_permissions"] {
            let s = ClaimMappingSettings {
                org_roles: Some(rule(bad)),
                org_permissions: None,
                ..ClaimMappingSettings::default()
            };
            let m = org_claims_json(Some(&c), &s, TokenTarget::AccessToken, &scope("openid"));
            assert_eq!(m.get("org_id"), Some(&json!(c.org_id.to_string())), "{bad}");
            assert_eq!(m.get("org_slug"), Some(&json!("acme")), "{bad}");
            assert_eq!(m.len(), 2, "{bad}: {m:?}");
        }
    }

    #[test]
    fn org_admin_scope_needs_the_permission_in_the_active_org() {
        let requested = scope("openid org:admin profile");
        let with = strings(&["org:admin", "x"]);
        let without = strings(&["x", "org:admin:read", "admin:organizations:write"]);

        let kept = bound_org_admin_scope(&requested, Some(&with));
        assert_eq!(kept, requested);

        for perms in [Some(without.as_slice()), Some(&[][..]), None] {
            let bounded = bound_org_admin_scope(&requested, perms);
            assert!(!bounded.contains(ORG_ADMIN_SCOPE), "{perms:?}");
            assert!(bounded.contains("openid") && bounded.contains("profile"));
            assert_eq!(bounded.len(), 2);
        }
    }

    #[test]
    fn bounding_leaves_other_scopes_alone() {
        let requested = scope("openid roles");
        assert_eq!(bound_org_admin_scope(&requested, None), requested);
    }
}
