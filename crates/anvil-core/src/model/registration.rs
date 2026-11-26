//! Dynamic client registration (RFC 7591) and Client ID Metadata Documents (CIMD) policy types.
//!
//! Both are disabled by default and always disabled for the system tenant
//! ([`super::TenantSettings::effective_dcr`], [`super::TenantSettings::effective_cimd`]).
//! `jwks_uri` is not supported for dynamic or CIMD clients in 0.4 (inline `jwks` only).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::ids::{InitialAccessTokenId, SecretHash, TenantId, str_enum};

/// How a client row came to exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientSource {
    /// Created by an administrator (console, admin API, declarative config).
    #[default]
    Static,
    /// Registered through `POST /register` (RFC 7591).
    Dynamic,
    /// Materialized from a Client ID Metadata Document (the `client_id` is an https URL).
    Cimd,
}

str_enum!(ClientSource {
    Static => "static",
    Dynamic => "dynamic",
    Cimd => "cimd",
});

/// Dynamic client registration policy of a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DcrPolicy {
    /// `POST /register` is not offered (default).
    #[default]
    Disabled,
    /// Registration requires an admin-issued initial access token (RFC 7591 §3), optionally with
    /// a redirect-URI host allow-list.
    AllowListed,
    /// Anyone may register (within the tenant's limits).
    Open,
}

str_enum!(DcrPolicy {
    Disabled => "disabled",
    AllowListed => "allow_listed",
    Open => "open",
});

/// Client ID Metadata Document policy of a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CimdPolicy {
    /// URL client ids are rejected (default).
    #[default]
    Disabled,
    /// Only documents hosted on `allowed_hosts` are accepted.
    AllowListed,
    /// Any https host passing the SSRF guard.
    Open,
}

str_enum!(CimdPolicy {
    Disabled => "disabled",
    AllowListed => "allow_listed",
    Open => "open",
});

/// Default cap on dynamically registered clients per tenant.
pub const DEFAULT_DCR_MAX_CLIENTS: u32 = 1000;
/// Default lower bound on how long a fetched metadata document is cached.
pub const DEFAULT_CIMD_MIN_CACHE_SECS: u32 = 300;
/// Default upper bound on how long a fetched metadata document is cached.
pub const DEFAULT_CIMD_MAX_CACHE_SECS: u32 = 86_400;

/// Dynamic client registration settings (stored in the tenant settings JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DcrSettings {
    pub policy: DcrPolicy,
    /// Redirect-URI hosts accepted at registration; empty = any host (subject to URI rules).
    pub allowed_redirect_hosts: Vec<String>,
    /// Scopes a registered client may ask for; empty = the tenant's default scopes only.
    pub allowed_scopes: Vec<String>,
    /// RFC 8707 resources a registered client may be granted.
    pub allowed_resources: Vec<String>,
    /// Whether registered confidential clients may use `client_credentials`.
    pub allow_client_credentials: bool,
    /// Most dynamic clients the tenant may hold.
    pub max_clients: u32,
}

impl Default for DcrSettings {
    fn default() -> Self {
        Self {
            policy: DcrPolicy::Disabled,
            allowed_redirect_hosts: Vec::new(),
            allowed_scopes: Vec::new(),
            allowed_resources: Vec::new(),
            allow_client_credentials: false,
            max_clients: DEFAULT_DCR_MAX_CLIENTS,
        }
    }
}

/// Client ID Metadata Document settings (stored in the tenant settings JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CimdSettings {
    pub policy: CimdPolicy,
    /// Hosts whose documents are accepted under [`CimdPolicy::AllowListed`].
    pub allowed_hosts: Vec<String>,
    /// The document's `Cache-Control: max-age` is clamped to `min_cache_secs..=max_cache_secs`.
    pub min_cache_secs: u32,
    pub max_cache_secs: u32,
}

impl Default for CimdSettings {
    fn default() -> Self {
        Self {
            policy: CimdPolicy::Disabled,
            allowed_hosts: Vec::new(),
            min_cache_secs: DEFAULT_CIMD_MIN_CACHE_SECS,
            max_cache_secs: DEFAULT_CIMD_MAX_CACHE_SECS,
        }
    }
}

/// An initial access token (RFC 7591 §3). Stored by hash only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialAccessToken {
    pub id: InitialAccessTokenId,
    pub tenant_id: TenantId,
    pub description: String,
    pub token_hash: SecretHash,
    pub expires_at: Option<OffsetDateTime>,
    /// `None` = unlimited uses until expiry or revocation.
    pub uses_remaining: Option<u32>,
    pub created_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

/// An initial access token to be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewInitialAccessToken {
    pub id: InitialAccessTokenId,
    pub description: String,
    pub token_hash: SecretHash,
    pub expires_at: Option<OffsetDateTime>,
    pub uses_remaining: Option<u32>,
    pub created_at: OffsetDateTime,
}

/// A fetched Client ID Metadata Document: the raw body (size-limited by the fetcher) and the
/// response's `Cache-Control: max-age`, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedMetadata {
    pub body: Vec<u8>,
    pub max_age_secs: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_names_round_trip() {
        for v in ClientSource::ALL {
            assert_eq!(ClientSource::parse(v.as_str()), Some(*v));
        }
        for v in DcrPolicy::ALL {
            assert_eq!(DcrPolicy::parse(v.as_str()), Some(*v));
        }
        for v in CimdPolicy::ALL {
            assert_eq!(CimdPolicy::parse(v.as_str()), Some(*v));
        }
        assert_eq!(ClientSource::default(), ClientSource::Static);
    }

    #[test]
    fn defaults_are_disabled_with_documented_limits() {
        let d = DcrSettings::default();
        assert_eq!(d.policy, DcrPolicy::Disabled);
        assert_eq!(d.max_clients, 1000);
        assert!(!d.allow_client_credentials);
        let c = CimdSettings::default();
        assert_eq!(c.policy, CimdPolicy::Disabled);
        assert_eq!((c.min_cache_secs, c.max_cache_secs), (300, 86_400));
        let parsed: DcrSettings = serde_json::from_str(r#"{"policy":"open"}"#).unwrap();
        assert_eq!(parsed.policy, DcrPolicy::Open);
        assert_eq!(parsed.max_clients, 1000);
    }
}
