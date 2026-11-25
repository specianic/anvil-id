//! OAuth clients.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::ids::{ClientId, SecretHash, TenantId, str_enum};

/// RFC 6749 §2.1 client type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    Confidential,
    Public,
}

str_enum!(ClientType {
    Confidential => "confidential",
    Public => "public",
});

/// OIDC Dynamic Client Registration `application_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationType {
    Web,
    Native,
}

str_enum!(ApplicationType {
    Web => "web",
    Native => "native",
});

/// Token endpoint authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
    None,
}

str_enum!(ClientAuthMethod {
    ClientSecretBasic => "client_secret_basic",
    ClientSecretPost => "client_secret_post",
    PrivateKeyJwt => "private_key_jwt",
    None => "none",
});

/// Grant types a client may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
    ClientCredentials,
}

str_enum!(GrantType {
    AuthorizationCode => "authorization_code",
    RefreshToken => "refresh_token",
    ClientCredentials => "client_credentials",
});

/// Format of the access tokens issued to a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenFormat {
    /// Signed JWT (RFC 9068 profile).
    #[default]
    Jwt,
    /// Random reference token, validated by introspection.
    Opaque,
}

str_enum!(TokenFormat {
    Jwt => "jwt",
    Opaque => "opaque",
});

/// When the consent screen is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentMode {
    /// Ask for every scope the user has not granted yet. Secure default; 0.1 clients get it on
    /// upgrade.
    #[default]
    Required,
    /// Skip the consent screen (first-party clients only).
    SkipFirstParty,
}

str_enum!(ConsentMode {
    Required => "required",
    SkipFirstParty => "skip_first_party",
});

/// A persisted client. `client_id` (the OAuth identifier) is unique per tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub id: ClientId,
    pub tenant_id: TenantId,
    pub client_id: String,
    pub name: String,
    pub client_type: ClientType,
    pub application_type: ApplicationType,
    pub auth_method: ClientAuthMethod,
    /// Digest of the client secret (never the secret itself).
    pub secret_hash: Option<SecretHash>,
    /// Inline JWKS JSON for `private_key_jwt`, parsed by anvil-jose.
    pub jwks: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<GrantType>,
    pub scopes: Vec<String>,
    pub require_pkce: bool,
    pub token_format: TokenFormat,
    pub consent_mode: ConsentMode,
    /// ID token signing algorithm; `None` = RS256.
    pub id_token_signed_response_alg: Option<String>,
    /// May introspect any token of the tenant. A confidential client may always introspect
    /// tokens issued to itself.
    pub can_introspect: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// A client to be created. `updated_at` starts equal to `created_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewClient {
    pub id: ClientId,
    pub client_id: String,
    pub name: String,
    pub client_type: ClientType,
    pub application_type: ApplicationType,
    pub auth_method: ClientAuthMethod,
    pub secret_hash: Option<SecretHash>,
    pub jwks: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<GrantType>,
    pub scopes: Vec<String>,
    pub require_pkce: bool,
    pub token_format: TokenFormat,
    pub consent_mode: ConsentMode,
    pub id_token_signed_response_alg: Option<String>,
    pub can_introspect: bool,
    pub created_at: OffsetDateTime,
}

/// Partial client update; `None` leaves a field unchanged. `jwks: Some(None)` clears the JWKS.
/// The secret changes only through `ClientRepo::set_secret_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientUpdate {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<GrantType>>,
    pub scopes: Option<Vec<String>>,
    pub require_pkce: Option<bool>,
    pub jwks: Option<Option<String>>,
    pub token_format: Option<TokenFormat>,
    pub consent_mode: Option<ConsentMode>,
    /// `Some(None)` resets to RS256.
    pub id_token_signed_response_alg: Option<Option<String>>,
    pub can_introspect: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_names_round_trip() {
        for v in ClientType::ALL {
            assert_eq!(ClientType::parse(v.as_str()), Some(*v));
        }
        for v in ApplicationType::ALL {
            assert_eq!(ApplicationType::parse(v.as_str()), Some(*v));
        }
        for v in ClientAuthMethod::ALL {
            assert_eq!(ClientAuthMethod::parse(v.as_str()), Some(*v));
        }
        for v in GrantType::ALL {
            assert_eq!(GrantType::parse(v.as_str()), Some(*v));
        }
        assert_eq!(GrantType::parse("password"), None);
        for v in TokenFormat::ALL {
            assert_eq!(TokenFormat::parse(v.as_str()), Some(*v));
        }
        for v in ConsentMode::ALL {
            assert_eq!(ConsentMode::parse(v.as_str()), Some(*v));
        }
        assert_eq!(TokenFormat::default(), TokenFormat::Jwt);
        assert_eq!(ConsentMode::default(), ConsentMode::Required);
    }
}
