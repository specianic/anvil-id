//! Consent grants: which scopes (and RFC 8707 resources) a user granted to a client.

use time::OffsetDateTime;

use super::ids::{ConsentId, UserId};

/// A stored consent grant, one per (tenant, user, client). `scopes` is the union of everything
/// granted so far; a revoked grant has `revoked_at` set and is ignored until granted again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGrant {
    pub id: ConsentId,
    pub user_id: UserId,
    pub client_id: String,
    pub scopes: Vec<String>,
    /// RFC 8707 resources covered by the grant, sorted and de-duplicated
    /// ([`normalize_resources`]). Empty for grants written before 0.4.
    pub resources: Vec<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

/// A consent to be granted (merged into an existing grant by `GrantRepo::upsert_consent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewConsent {
    pub id: ConsentId,
    pub user_id: UserId,
    pub client_id: String,
    pub scopes: Vec<String>,
    /// RFC 8707 resources covered by the grant, sorted and de-duplicated
    /// ([`normalize_resources`]). Empty for grants written before 0.4.
    pub resources: Vec<String>,
    pub created_at: OffsetDateTime,
}

/// Sorts and de-duplicates a resource list (the stored form of [`ConsentGrant::resources`]).
pub fn normalize_resources(resources: &[String]) -> Vec<String> {
    let mut out = resources.to_vec();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resources_are_sorted_and_deduplicated() {
        let r = normalize_resources(&[
            "https://b.example".into(),
            "https://a.example".into(),
            "https://b.example".into(),
        ]);
        assert_eq!(
            r,
            vec![
                "https://a.example".to_owned(),
                "https://b.example".to_owned()
            ]
        );
        assert!(normalize_resources(&[]).is_empty());
    }
}
