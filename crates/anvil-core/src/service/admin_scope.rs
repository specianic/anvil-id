//! Management API scopes, defined once.
//!
//! - `admin:read` grants read access to every resource; `admin:write` grants read and write access
//!   to every resource.
//! - `admin:{tenants|clients|users|sessions|audit|settings|organizations}:read` grants read access to that
//!   resource only;
//!   `admin:{resource}:write` grants read and write access to that resource only.
//! - `admin:users:export` ([`ADMIN_USERS_EXPORT`], ADM-09) is a third access kind: bulk and GDPR
//!   user export. It is satisfied only by itself or by the full `admin:write` umbrella, never by
//!   `admin:read`, `admin:users:read` or `admin:users:write`: reading users page by page is not
//!   the same grant as pulling every user out in one call. Installations upgraded from 0.4 or
//!   1.0.0-beta.1 get it through `admin:write`.
//!
//! [`scope_covers`] is THE coverage rule. Route checks ([`scope_satisfies`],
//! [`export_scope_satisfied`]) and the role rules in [`crate::service::role`] (effective scopes,
//! token bounding, escalation) all go through it.
//!
//! The admin API (02-16) checks every route with [`scope_satisfies`] and lists
//! [`ALL_ADMIN_SCOPES`] in its OpenAPI security scheme.

use crate::model::Scope;

/// Broad read scope.
pub const ADMIN_READ: &str = "admin:read";
/// Broad write scope (implies [`ADMIN_READ`]).
pub const ADMIN_WRITE: &str = "admin:write";

/// Bulk/GDPR user export (ADM-09). Covered only by itself and [`ADMIN_WRITE`].
pub const ADMIN_USERS_EXPORT: &str = "admin:users:export";

/// Every admin scope, broad scopes first.
pub const ALL_ADMIN_SCOPES: &[&str] = &[
    ADMIN_READ,
    ADMIN_WRITE,
    "admin:tenants:read",
    "admin:tenants:write",
    "admin:clients:read",
    "admin:clients:write",
    "admin:users:read",
    "admin:users:write",
    "admin:sessions:read",
    "admin:sessions:write",
    "admin:audit:read",
    "admin:audit:write",
    "admin:settings:read",
    "admin:settings:write",
    "admin:organizations:read",
    "admin:organizations:write",
    ADMIN_USERS_EXPORT,
];

/// Scope of an organization admin's token in an application tenant (decision Q1). Not an
/// `admin:*` token ([`is_reserved_admin_token`] stays false): it is granted only at issuance,
/// bounded per organization by the user's org-role permissions, and accepted only on that org's
/// admin sub-routes together with a matching `org_id`. Its reservation rules (DCR, client scopes)
/// land with the org admin path.
pub const ORG_ADMIN_SCOPE: &str = "org:admin";

/// A management resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    Tenants,
    Clients,
    Users,
    /// User sessions (list, revoke).
    Sessions,
    /// The audit log.
    Audit,
    /// Tenant settings managed apart from the tenant record (signing keys, CAPTCHA, email).
    Settings,
    /// Organizations and everything they own (members, invitations, org roles, org
    /// connections, domains).
    Organizations,
}

impl Resource {
    /// Resource name as used in scopes.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tenants => "tenants",
            Self::Clients => "clients",
            Self::Users => "users",
            Self::Sessions => "sessions",
            Self::Audit => "audit",
            Self::Settings => "settings",
            Self::Organizations => "organizations",
        }
    }
}

/// The kind of access a route needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    Read,
    Write,
}

/// The per-resource scope string, e.g. `admin:users:write`.
pub fn resource_scope(resource: Resource, access: Access) -> String {
    let access = match access {
        Access::Read => "read",
        Access::Write => "write",
    };
    format!("admin:{}:{access}", resource.as_str())
}

/// Whether admin scope `held` grants admin scope `wanted`, the single coverage rule:
///
/// - every scope covers itself;
/// - `admin:write` covers every admin scope, including [`ADMIN_USERS_EXPORT`];
/// - `admin:read` covers every `:read` scope (so never a write scope or the export scope);
/// - `admin:{r}:write` covers `admin:{r}:read` (so never `admin:users:export`).
pub fn scope_covers(held: &str, wanted: &str) -> bool {
    if held == wanted || held == ADMIN_WRITE {
        return true;
    }
    if held == ADMIN_READ {
        return wanted.ends_with(":read");
    }
    match (held.strip_suffix(":write"), wanted.strip_suffix(":read")) {
        (Some(h), Some(w)) => h == w,
        _ => false,
    }
}

/// Whether `granted` allows `access` on `resource`.
pub fn scope_satisfies(granted: &Scope, resource: Resource, access: Access) -> bool {
    let wanted = resource_scope(resource, access);
    granted.iter().any(|held| scope_covers(held, &wanted))
}

/// Whether `granted` allows bulk/GDPR user export: only [`ADMIN_USERS_EXPORT`] or
/// [`ADMIN_WRITE`].
pub fn export_scope_satisfied(granted: &Scope) -> bool {
    granted
        .iter()
        .any(|held| scope_covers(held, ADMIN_USERS_EXPORT))
}

/// Whether `token` is one of the admin scopes.
pub fn is_admin_scope(token: &str) -> bool {
    ALL_ADMIN_SCOPES.contains(&token)
}

/// Whether `token` lies in the namespace reserved for the admin API: `admin` itself or anything
/// starting with `admin:`. Covers every [`ALL_ADMIN_SCOPES`] entry and any admin scope added
/// later. Clients outside the system tenant (static, DCR, CIMD) never carry such a token, and DCR
/// settings never allow one.
pub fn is_reserved_admin_token(token: &str) -> bool {
    token == "admin" || token.starts_with("admin:")
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESOURCES: [Resource; 7] = [
        Resource::Tenants,
        Resource::Clients,
        Resource::Users,
        Resource::Sessions,
        Resource::Audit,
        Resource::Settings,
        Resource::Organizations,
    ];

    fn scope(s: &str) -> Scope {
        Scope::parse(s).unwrap()
    }

    #[test]
    fn admin_read_grants_read_everywhere_but_no_write() {
        let s = scope("admin:read");
        for r in RESOURCES {
            assert!(scope_satisfies(&s, r, Access::Read));
            assert!(!scope_satisfies(&s, r, Access::Write));
        }
    }

    #[test]
    fn admin_write_grants_everything() {
        let s = scope("admin:write");
        for r in RESOURCES {
            assert!(scope_satisfies(&s, r, Access::Read));
            assert!(scope_satisfies(&s, r, Access::Write));
        }
    }

    #[test]
    fn resource_write_grants_only_that_resource() {
        let s = scope("admin:users:write");
        assert!(scope_satisfies(&s, Resource::Users, Access::Read));
        assert!(scope_satisfies(&s, Resource::Users, Access::Write));
        for r in RESOURCES.into_iter().filter(|r| *r != Resource::Users) {
            assert!(!scope_satisfies(&s, r, Access::Read));
            assert!(!scope_satisfies(&s, r, Access::Write));
        }
    }

    #[test]
    fn resource_read_grants_only_read_on_that_resource() {
        let s = scope("admin:clients:read");
        assert!(scope_satisfies(&s, Resource::Clients, Access::Read));
        assert!(!scope_satisfies(&s, Resource::Clients, Access::Write));
        assert!(!scope_satisfies(&s, Resource::Users, Access::Read));
    }

    #[test]
    fn unrelated_scopes_grant_nothing() {
        for raw in [
            "openid profile email",
            "admin",
            "admin:users",
            "admin:read:x",
        ] {
            let s = scope(raw);
            for r in RESOURCES {
                assert!(!scope_satisfies(&s, r, Access::Read), "{raw}");
                assert!(!scope_satisfies(&s, r, Access::Write), "{raw}");
            }
        }
        assert!(!scope_satisfies(
            &Scope::default(),
            Resource::Users,
            Access::Read
        ));
    }

    #[test]
    fn all_admin_scopes_cover_every_resource_scope() {
        for r in RESOURCES {
            for a in [Access::Read, Access::Write] {
                assert!(is_admin_scope(&resource_scope(r, a)));
            }
        }
        // Two umbrellas, read and write per resource, plus the export scope.
        assert_eq!(ALL_ADMIN_SCOPES.len(), 2 + 2 * RESOURCES.len() + 1);
        assert!(is_admin_scope(ADMIN_USERS_EXPORT));
        assert!(is_admin_scope("admin:sessions:write"));
        assert!(is_admin_scope("admin:audit:read"));
        assert!(is_admin_scope("admin:settings:write"));
        assert!(is_admin_scope("admin:organizations:read"));
        assert!(is_admin_scope("admin:organizations:write"));
        assert!(!is_admin_scope("openid"));
        assert!(!is_admin_scope(ORG_ADMIN_SCOPE));
    }

    #[test]
    fn reserved_admin_tokens() {
        for t in ["admin", "admin:read", "admin:anything", "admin:"] {
            assert!(is_reserved_admin_token(t), "{t}");
        }
        for t in ALL_ADMIN_SCOPES {
            assert!(is_reserved_admin_token(t), "{t}");
        }
        for t in ["openid", "administrator", "xadmin:read", "Admin:read", ""] {
            assert!(!is_reserved_admin_token(t), "{t}");
        }
        // The org admin scope is not an admin API token: it never satisfies an admin route.
        assert_eq!(ORG_ADMIN_SCOPE, "org:admin");
        assert!(!is_reserved_admin_token(ORG_ADMIN_SCOPE));
        let s = scope(ORG_ADMIN_SCOPE);
        for r in RESOURCES {
            assert!(!scope_satisfies(&s, r, Access::Read));
            assert!(!scope_satisfies(&s, r, Access::Write));
        }
    }

    #[test]
    fn export_scope_not_implied_by_admin_read() {
        assert!(!scope_covers(ADMIN_READ, ADMIN_USERS_EXPORT));
        assert!(!export_scope_satisfied(&scope("admin:read")));
    }

    #[test]
    fn export_scope_not_implied_by_users_read() {
        assert!(!scope_covers("admin:users:read", ADMIN_USERS_EXPORT));
        assert!(!export_scope_satisfied(&scope("admin:users:read")));
    }

    #[test]
    fn export_scope_not_implied_by_users_write() {
        assert!(!scope_covers("admin:users:write", ADMIN_USERS_EXPORT));
        assert!(!export_scope_satisfied(&scope(
            "admin:read admin:users:read admin:users:write"
        )));
    }

    #[test]
    fn export_scope_implied_by_admin_write() {
        assert!(scope_covers(ADMIN_WRITE, ADMIN_USERS_EXPORT));
        assert!(export_scope_satisfied(&scope("admin:write")));
        assert!(export_scope_satisfied(&scope("admin:users:export")));
        // The export scope grants nothing else.
        let s = scope("admin:users:export");
        for r in RESOURCES {
            assert!(!scope_satisfies(&s, r, Access::Read));
            assert!(!scope_satisfies(&s, r, Access::Write));
        }
        assert!(!export_scope_satisfied(&scope("admin:users admin:export")));
    }
}
