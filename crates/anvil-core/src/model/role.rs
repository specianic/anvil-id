//! Tenant-scoped roles and their permission sets (ADM-05).
//!
//! 0.4 is plain role -> permission sets; a fine-grained engine is deferred (D5). Phase 6 adds
//! organizations with a hybrid model on one assignment table: a tenant role (`org_id` `None`)
//! can be assigned tenant-wide or inside one org, and an org-owned role (`org_id` `Some`) can
//! only be assigned inside its org.

use time::OffsetDateTime;

use super::ids::{OrgId, RoleId, TenantId, UserId};
use crate::error::CoreError;

/// Name of the role that grants full administration in the system tenant. System-tenant roles map
/// to admin API scopes; at least one user must keep this role.
pub const SYSTEM_ADMIN_ROLE: &str = "administrator";

/// Most permissions one role may carry.
pub const MAX_PERMISSIONS_PER_ROLE: usize = 100;

/// Longest permission string, in bytes.
pub const MAX_PERMISSION_LEN: usize = 128;

/// Longest role name, in bytes.
pub const MAX_ROLE_NAME_LEN: usize = 64;

/// A persisted role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: RoleId,
    pub tenant_id: TenantId,
    /// `None` = tenant role; `Some` = role owned by that organization.
    pub org_id: Option<OrgId>,
    /// Unique per tenant (and org); see [`validate_role_name`].
    pub name: String,
    pub description: String,
    /// Sorted, de-duplicated permission strings; see [`validate_permission`].
    pub permissions: Vec<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// A role to be created. `updated_at` starts equal to `created_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRole {
    pub id: RoleId,
    /// `None` = tenant role; `Some` = role owned by that organization.
    pub org_id: Option<OrgId>,
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub created_at: OffsetDateTime,
}

/// One role assignment: `org_id` `None` = tenant-wide; `Some` = the role holds only while the
/// user acts in that organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoleAssignment {
    pub role_id: RoleId,
    pub user_id: UserId,
    pub org_id: Option<OrgId>,
}

/// Partial role update; `None` leaves a field unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RoleUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
}

/// Validates a role name: `^[a-z0-9][a-z0-9_.-]{0,63}$`.
pub fn validate_role_name(name: &str) -> Result<(), CoreError> {
    let mut chars = name.chars();
    let ok = match chars.next() {
        Some(first) => {
            (first.is_ascii_lowercase() || first.is_ascii_digit())
                && name.len() <= MAX_ROLE_NAME_LEN
                && chars.all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-')
                })
        }
        None => false,
    };
    if ok {
        Ok(())
    } else {
        Err(CoreError::Validation {
            field: "name",
            message: "role names are 1-64 characters of a-z, 0-9, '_', '.' or '-', starting with a letter or digit".to_owned(),
        })
    }
}

/// Validates one permission string: `^[A-Za-z0-9:._/-]{1,128}$`.
pub fn validate_permission(permission: &str) -> Result<(), CoreError> {
    let ok = !permission.is_empty()
        && permission.len() <= MAX_PERMISSION_LEN
        && permission
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '/' | '-'));
    if ok {
        Ok(())
    } else {
        Err(CoreError::Validation {
            field: "permissions",
            message: "permissions are 1-128 characters of A-Z, a-z, 0-9, ':', '.', '_', '/' or '-'"
                .to_owned(),
        })
    }
}

/// Validates a permission set and returns it sorted and de-duplicated.
pub fn normalize_permissions(permissions: &[String]) -> Result<Vec<String>, CoreError> {
    for p in permissions {
        validate_permission(p)?;
    }
    let mut out = permissions.to_vec();
    out.sort();
    out.dedup();
    if out.len() > MAX_PERMISSIONS_PER_ROLE {
        return Err(CoreError::Validation {
            field: "permissions",
            message: format!("a role may carry at most {MAX_PERMISSIONS_PER_ROLE} permissions"),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_names_accept_and_reject() {
        for good in [
            "admin",
            "a",
            "0",
            "billing.reader",
            "ops-team_1",
            &"a".repeat(64),
        ] {
            assert!(
                validate_role_name(good).is_ok(),
                "{good:?} must be accepted"
            );
        }
        for bad in [
            "",
            "Admin",
            "-lead",
            "_x",
            ".x",
            "with space",
            "ümlaut",
            "a/b",
            &"a".repeat(65),
        ] {
            assert!(validate_role_name(bad).is_err(), "{bad:?} must be rejected");
        }
        assert!(validate_role_name(SYSTEM_ADMIN_ROLE).is_ok());
    }

    #[test]
    fn permissions_accept_and_reject() {
        for good in [
            "read",
            "docs:write",
            "api/v1.users_read-all",
            &"p".repeat(128),
        ] {
            assert!(
                validate_permission(good).is_ok(),
                "{good:?} must be accepted"
            );
        }
        for bad in ["", "a b", "a*", "a,b", "\"x\"", "é", &"p".repeat(129)] {
            assert!(
                validate_permission(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn normalize_sorts_dedups_and_caps() {
        let p = normalize_permissions(&["b".into(), "a".into(), "b".into()]).unwrap();
        assert_eq!(p, vec!["a".to_owned(), "b".to_owned()]);
        let max: Vec<String> = (0..MAX_PERMISSIONS_PER_ROLE)
            .map(|i| format!("p{i}"))
            .collect();
        assert!(normalize_permissions(&max).is_ok());
        let mut over = max.clone();
        over.push("extra".into());
        assert!(normalize_permissions(&over).is_err());
        // Duplicates do not count towards the cap.
        let mut dup = max;
        dup.push("p0".into());
        assert!(normalize_permissions(&dup).is_ok());
        assert!(normalize_permissions(&["bad perm".into()]).is_err());
    }
}
