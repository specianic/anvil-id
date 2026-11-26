//! Upstream identity-provider connections (social presets, generic OIDC, generic OAuth2) and the
//! links between local users and upstream identities (AUTH-07, AUTH-11, SEC-03).
//!
//! The provider client secret is never part of [`ConnectionConfig`]: it is stored separately as
//! `secret_enc`, sealed with the KEK under [`CONNECTION_SECRET_PURPOSE`] and
//! [`connection_aad`].

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use super::ids::{ConnectionId, IdentityLinkId, OrgId, TenantId, UserId, str_enum};
use super::saml::SamlConfig;

/// KEK purpose for a sealed upstream client secret (Apple: the `.p8` private key PEM).
pub const CONNECTION_SECRET_PURPOSE: &str = "anvilid/connection-secret/v1";

/// AAD of a sealed connection secret: tenant id bytes followed by connection id bytes, so a
/// sealed secret cannot be moved to another connection or tenant.
pub fn connection_aad(tenant: TenantId, id: ConnectionId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(tenant.0.as_bytes());
    aad.extend_from_slice(id.0.as_bytes());
    aad
}

/// Kind of a connection (derived from its config; stored for listing and filtering).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionKind {
    Google,
    Apple,
    Microsoft,
    Github,
    Oidc,
    Oauth2,
    Saml,
}

str_enum!(ConnectionKind {
    Google => "google",
    Apple => "apple",
    Microsoft => "microsoft",
    Github => "github",
    Oidc => "oidc",
    Oauth2 => "oauth2",
    Saml => "saml",
});

impl ConnectionKind {
    /// Default of [`Connection::trust_email_verified`] for a new connection of this kind: the
    /// presets whose providers only assert verified addresses (Google, Apple, GitHub's verified
    /// primary email) trust them; Microsoft (multi-tenant, admin-controlled addresses) and the
    /// generic kinds do not.
    pub fn default_email_trust(self) -> bool {
        matches!(self, Self::Google | Self::Apple | Self::Github)
    }
}

/// Social provider preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocialProvider {
    Google,
    Apple,
    Microsoft,
    Github,
}

str_enum!(SocialProvider {
    Google => "google",
    Apple => "apple",
    Microsoft => "microsoft",
    Github => "github",
});

impl SocialProvider {
    pub fn kind(self) -> ConnectionKind {
        match self {
            Self::Google => ConnectionKind::Google,
            Self::Apple => ConnectionKind::Apple,
            Self::Microsoft => ConnectionKind::Microsoft,
            Self::Github => ConnectionKind::Github,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Endpoint overrides of a social preset (tests point presets at mock IdPs; operators rarely
/// need them). `None` = the preset's built-in value.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EndpointOverrides {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    /// GitHub REST API base (`https://api.github.com`).
    pub api_base_url: Option<String>,
}

/// Apple Sign In specifics: the client secret is an ES256 JWT signed with the team's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleConfig {
    pub team_id: String,
    pub key_id: String,
}

/// A social preset connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocialConfig {
    pub provider: SocialProvider,
    pub client_id: String,
    /// Requested scopes; empty = the preset's defaults.
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub endpoints: EndpointOverrides,
    /// Microsoft only: `common` | `organizations` | `consumers` | a tenant UUID. `None` = `common`.
    #[serde(default)]
    pub microsoft_tenant: Option<String>,
    /// Microsoft only: accepted `tid` values (empty = any).
    #[serde(default)]
    pub allowed_tenants: Vec<String>,
    /// Google only: accepted `hd` values (empty = any).
    #[serde(default)]
    pub hosted_domains: Vec<String>,
    /// Apple only.
    #[serde(default)]
    pub apple: Option<AppleConfig>,
}

/// A generic OpenID Connect upstream (discovery at `{issuer}/.well-known/openid-configuration`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_true")]
    pub use_pkce: bool,
    /// Also call the UserInfo endpoint after the ID token was validated.
    #[serde(default)]
    pub fetch_userinfo: bool,
}

/// Where the identity claims are found in a generic OAuth2 profile response (JSON pointers,
/// RFC 6901, e.g. `/id`, `/email`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimMapping {
    pub subject: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// A generic OAuth2 upstream (no ID token; identity from a profile endpoint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuth2Config {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub client_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_true")]
    pub use_pkce: bool,
    pub mapping: ClaimMapping,
}

/// Connection configuration, stored as JSON tagged by `type` (ARCHITECTURE §19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConnectionConfig {
    Social(SocialConfig),
    Oidc(OidcConfig),
    Oauth2(OAuth2Config),
    /// A SAML 2.0 IdP (experimental, behind an operator flag). Runs only through the SAML
    /// service, never through the OIDC/OAuth upstream path.
    Saml(SamlConfig),
}

impl ConnectionConfig {
    pub fn kind(&self) -> ConnectionKind {
        match self {
            Self::Social(s) => s.provider.kind(),
            Self::Oidc(_) => ConnectionKind::Oidc,
            Self::Oauth2(_) => ConnectionKind::Oauth2,
            Self::Saml(_) => ConnectionKind::Saml,
        }
    }

    /// The upstream OAuth `client_id`; `None` for SAML, which has no OAuth client.
    pub fn client_id(&self) -> Option<&str> {
        match self {
            Self::Social(s) => Some(&s.client_id),
            Self::Oidc(o) => Some(&o.client_id),
            Self::Oauth2(o) => Some(&o.client_id),
            Self::Saml(_) => None,
        }
    }
}

/// A persisted connection. `slug` is unique per tenant and appears in the callback URL.
#[derive(Clone, PartialEq, Eq)]
pub struct Connection {
    pub id: ConnectionId,
    pub tenant_id: TenantId,
    /// `Some` = an organization's enterprise connection (never shown on the tenant sign-in
    /// page; reached through domain routing or the `organization` parameter).
    pub org_id: Option<OrgId>,
    pub slug: String,
    pub display_name: String,
    pub enabled: bool,
    pub config: ConnectionConfig,
    /// KEK-sealed client secret ([`CONNECTION_SECRET_PURPOSE`], [`connection_aad`]).
    pub secret_enc: Option<Vec<u8>>,
    /// Treat the upstream's `email_verified` as proof of address ownership (auto-linking).
    pub trust_email_verified: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Connection {
    pub fn kind(&self) -> ConnectionKind {
        self.config.kind()
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("org_id", &self.org_id)
            .field("slug", &self.slug)
            .field("display_name", &self.display_name)
            .field("enabled", &self.enabled)
            .field("config", &self.config)
            .field("secret_enc", &self.secret_enc.as_ref().map(|_| "<sealed>"))
            .field("trust_email_verified", &self.trust_email_verified)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// A connection to be created. `updated_at` starts equal to `created_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewConnection {
    pub id: ConnectionId,
    /// `Some` = an organization's enterprise connection. Fixed at creation.
    pub org_id: Option<OrgId>,
    pub slug: String,
    pub display_name: String,
    pub enabled: bool,
    pub config: ConnectionConfig,
    pub secret_enc: Option<Vec<u8>>,
    pub trust_email_verified: bool,
    pub created_at: OffsetDateTime,
}

/// Partial connection update; `None` leaves a field unchanged. The secret changes only through
/// `ConnectionRepo::set_secret`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectionUpdate {
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<ConnectionConfig>,
    pub trust_email_verified: Option<bool>,
}

/// A local user linked to an upstream identity. (tenant, connection, subject) is unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityLink {
    pub id: IdentityLinkId,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub connection_id: ConnectionId,
    /// The upstream subject (`sub`, GitHub numeric id, mapped subject).
    pub subject: String,
    /// The upstream email when the link was made (for display; never used to sign in).
    pub email_at_link: Option<String>,
    /// Provider-specific identifiers (e.g. Microsoft `tid`/`oid`). Never tokens or secrets.
    pub metadata: Map<String, Value>,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
}

/// An identity link to be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIdentityLink {
    pub id: IdentityLinkId,
    pub user_id: UserId,
    pub connection_id: ConnectionId,
    pub subject: String,
    pub email_at_link: Option<String>,
    pub metadata: Map<String, Value>,
    pub created_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_names_round_trip_and_email_trust_defaults() {
        for v in ConnectionKind::ALL {
            assert_eq!(ConnectionKind::parse(v.as_str()), Some(*v));
        }
        for v in SocialProvider::ALL {
            assert_eq!(SocialProvider::parse(v.as_str()), Some(*v));
            assert_eq!(v.kind().as_str(), v.as_str());
        }
        assert!(ConnectionKind::Google.default_email_trust());
        assert!(ConnectionKind::Apple.default_email_trust());
        assert!(ConnectionKind::Github.default_email_trust());
        assert!(!ConnectionKind::Microsoft.default_email_trust());
        assert!(!ConnectionKind::Oidc.default_email_trust());
        assert!(!ConnectionKind::Oauth2.default_email_trust());
    }

    #[test]
    fn config_is_tagged_json_with_defaults() {
        let social: ConnectionConfig =
            serde_json::from_str(r#"{"type":"social","provider":"google","client_id":"abc"}"#)
                .unwrap();
        assert_eq!(social.kind(), ConnectionKind::Google);
        assert_eq!(social.client_id(), Some("abc"));
        let ConnectionConfig::Social(s) = &social else {
            panic!("social")
        };
        assert!(s.scopes.is_empty());
        assert_eq!(s.endpoints, EndpointOverrides::default());
        assert_eq!(s.apple, None);

        let oidc: ConnectionConfig = serde_json::from_str(
            r#"{"type":"oidc","issuer":"https://idp.example","client_id":"c"}"#,
        )
        .unwrap();
        let ConnectionConfig::Oidc(o) = &oidc else {
            panic!("oidc")
        };
        assert!(o.use_pkce, "PKCE defaults to on");
        assert!(!o.fetch_userinfo);

        let oauth2 = ConnectionConfig::Oauth2(OAuth2Config {
            authorization_endpoint: "https://a.example/auth".into(),
            token_endpoint: "https://a.example/token".into(),
            userinfo_endpoint: "https://a.example/me".into(),
            client_id: "c".into(),
            scopes: vec!["read".into()],
            use_pkce: false,
            mapping: ClaimMapping {
                subject: "/id".into(),
                email: Some("/email".into()),
                email_verified: None,
                name: None,
            },
        });
        let json = serde_json::to_value(&oauth2).unwrap();
        assert_eq!(json["type"], "oauth2");
        assert_eq!(
            serde_json::from_value::<ConnectionConfig>(json).unwrap(),
            oauth2
        );
        assert!(
            serde_json::from_str::<ConnectionConfig>(r#"{"type":"saml"}"#).is_err(),
            "a saml config without its required fields is rejected"
        );
        assert!(
            serde_json::from_str::<ConnectionConfig>(r#"{"type":"ldap"}"#).is_err(),
            "unknown types are rejected"
        );
        let saml: ConnectionConfig = serde_json::from_str(
            r#"{"type":"saml","idp_entity_id":"e","sso_url":"https://i/sso","signing_certs":["c"]}"#,
        )
        .unwrap();
        assert_eq!(saml.kind(), ConnectionKind::Saml);
        assert_eq!(saml.client_id(), None);
    }

    #[test]
    fn aad_binds_tenant_and_connection() {
        let t = TenantId::new_v7();
        let c = ConnectionId::new_v7();
        let aad = connection_aad(t, c);
        assert_eq!(aad.len(), 32);
        assert_eq!(&aad[..16], t.0.as_bytes());
        assert_eq!(&aad[16..], c.0.as_bytes());
        assert_ne!(aad, connection_aad(t, ConnectionId::new_v7()));
    }

    #[test]
    fn debug_hides_sealed_secret() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let conn = Connection {
            id: ConnectionId::new_v7(),
            tenant_id: TenantId::new_v7(),
            org_id: None,
            slug: "google".into(),
            display_name: "Google".into(),
            enabled: true,
            config: ConnectionConfig::Oidc(OidcConfig {
                issuer: "https://idp.example".into(),
                client_id: "c".into(),
                scopes: vec![],
                use_pkce: true,
                fetch_userinfo: false,
            }),
            secret_enc: Some(vec![0xAB; 40]),
            trust_email_verified: false,
            created_at: now,
            updated_at: now,
        };
        let dbg = format!("{conn:?}");
        assert!(dbg.contains("<sealed>"));
        assert!(!dbg.contains("[171"));
    }
}
