//! Wire types of the management API (JSON, snake_case) and their conversions to and from the
//! domain types. anvil-core stays free of OpenAPI concerns, so every type that appears in the
//! spec is defined here; the enums mirror the domain enums one to one.

use anvil_core::model::{
    Address as CoreAddress, ApplicationType as CoreApplicationType, Client,
    ClientAuthMethod as CoreClientAuthMethod, ClientType as CoreClientType,
    GrantType as CoreGrantType, Page, RegistrationMode as CoreRegistrationMode,
    StandardClaims as CoreStandardClaims, Tenant, TenantSettings as CoreTenantSettings, User,
    UserStatus as CoreUserStatus,
};
use anvil_core::service::client::{ClientInput, ClientPatch};
use anvil_core::service::tenant::{NewTenantInput, TenantPatch};
use anvil_core::service::user::{UserInput, UserPatch};
use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Mirrors a fieldless domain enum as a wire enum with the same snake_case names.
macro_rules! wire_enum {
    ($(#[$meta:meta])* $dto:ident => $core:ident { $($variant:ident),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
        #[serde(rename_all = "snake_case")]
        pub enum $dto {
            $($variant),+
        }

        impl From<$dto> for $core {
            fn from(v: $dto) -> Self {
                match v {
                    $($dto::$variant => Self::$variant),+
                }
            }
        }

        impl From<$core> for $dto {
            fn from(v: $core) -> Self {
                match v {
                    $($core::$variant => Self::$variant),+
                }
            }
        }
    };
}

wire_enum!(
    /// Who may self-register in a tenant.
    RegistrationMode => CoreRegistrationMode { Open, InviteOnly, Disabled }
);
wire_enum!(
    /// OAuth client type (RFC 6749 §2.1).
    ClientType => CoreClientType { Confidential, Public }
);
wire_enum!(
    /// OpenID Connect application type.
    ApplicationType => CoreApplicationType { Web, Native }
);
wire_enum!(
    /// Token endpoint authentication method.
    ClientAuthMethod => CoreClientAuthMethod {
        ClientSecretBasic,
        ClientSecretPost,
        PrivateKeyJwt,
        None,
    }
);
wire_enum!(
    /// OAuth grant type.
    GrantType => CoreGrantType { AuthorizationCode, RefreshToken, ClientCredentials }
);
wire_enum!(
    /// Whether a user may sign in.
    UserStatus => CoreUserStatus { Active, Blocked }
);

/// RFC 3339 timestamp. The domain only holds times inside years 0..=9999, which always format.
fn ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// Deserialises a present field (including `null`) as `Some(..)`, so PATCH bodies can tell
/// "absent" (leave unchanged) from `null` (clear).
fn double_option<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

fn map_vec<A: Copy, B: From<A>>(v: &[A]) -> Vec<B> {
    v.iter().copied().map(B::from).collect()
}

// ---------------------------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------------------------

/// One validation failure.
#[derive(Debug, Serialize, ToSchema)]
pub struct FieldError {
    pub field: String,
    pub message: String,
}

/// RFC 9457 problem details (`application/problem+json`).
#[derive(Debug, Serialize, ToSchema)]
pub struct Problem {
    /// `urn:anvilid:problem:{code}`.
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    /// Field errors (validation failures only; empty otherwise).
    pub errors: Vec<FieldError>,
}

/// Cursor pagination: pass the previous page's `next_cursor` as `after`.
#[derive(Debug, Clone, Copy, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    /// Return items after this id (the previous page's `next_cursor`).
    pub after: Option<Uuid>,
    /// Page size, 1 to 200 (default 50).
    #[param(minimum = 1, maximum = 200)]
    pub limit: Option<u32>,
}

// ---------------------------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------------------------

/// Per-tenant settings.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TenantSettings {
    pub registration: RegistrationMode,
    /// Users must verify their email address before they can sign in.
    pub require_verified_email: bool,
}

impl Default for TenantSettings {
    fn default() -> Self {
        CoreTenantSettings::default().into()
    }
}

impl From<CoreTenantSettings> for TenantSettings {
    fn from(s: CoreTenantSettings) -> Self {
        Self {
            registration: s.registration.into(),
            require_verified_email: s.require_verified_email,
        }
    }
}

impl From<TenantSettings> for CoreTenantSettings {
    fn from(s: TenantSettings) -> Self {
        Self {
            registration: s.registration.into(),
            require_verified_email: s.require_verified_email,
            // Phase 3 settings (signing algorithms, CAPTCHA) get wire fields in 03-23; until then
            // the wire type cannot set them and they keep their defaults.
            ..CoreTenantSettings::default()
        }
    }
}

/// A tenant.
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantView {
    pub id: Uuid,
    /// Immutable; path-based issuers are `{public_url}/t/{slug}`.
    pub slug: String,
    pub display_name: String,
    /// Custom host for host-based serving.
    pub host: Option<String>,
    pub settings: TenantSettings,
    #[schema(format = DateTime)]
    pub created_at: String,
}

impl From<Tenant> for TenantView {
    fn from(t: Tenant) -> Self {
        Self {
            id: t.id.0,
            slug: t.slug,
            display_name: t.display_name,
            host: t.host,
            settings: t.settings.into(),
            created_at: ts(t.created_at),
        }
    }
}

/// One page of tenants.
#[derive(Debug, Serialize, ToSchema)]
pub struct TenantList {
    pub items: Vec<TenantView>,
    /// Present if and only if more items follow.
    pub next_cursor: Option<Uuid>,
}

impl From<Page<Tenant>> for TenantList {
    fn from(p: Page<Tenant>) -> Self {
        Self {
            items: p.items.into_iter().map(Into::into).collect(),
            next_cursor: p.next_cursor,
        }
    }
}

/// Body of `POST /tenants`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTenant {
    /// 2-63 characters of a-z, 0-9 and '-'; `system` and `default` are reserved.
    pub slug: String,
    pub display_name: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub settings: TenantSettings,
}

impl From<CreateTenant> for NewTenantInput {
    fn from(c: CreateTenant) -> Self {
        Self {
            slug: c.slug,
            display_name: c.display_name,
            host: c.host,
            settings: c.settings.into(),
        }
    }
}

/// Body of `PATCH /tenants/{slug}`. Absent fields stay unchanged; `host: null` clears the host.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateTenant {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub host: Option<Option<String>>,
    #[serde(default)]
    pub settings: Option<TenantSettings>,
}

impl From<UpdateTenant> for TenantPatch {
    fn from(u: UpdateTenant) -> Self {
        Self {
            display_name: u.display_name,
            host: u.host,
            settings: u.settings.map(Into::into),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------------------------

/// A registered OAuth client. `client_secret` is only present in the response that created the
/// client; it is never stored in plaintext and cannot be read again.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientView {
    pub client_id: String,
    pub name: String,
    pub client_type: ClientType,
    pub application_type: ApplicationType,
    pub auth_method: ClientAuthMethod,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<GrantType>,
    pub scopes: Vec<String>,
    pub require_pkce: bool,
    /// Inline public JWK Set (`private_key_jwt` only).
    #[schema(value_type = Option<Object>)]
    pub jwks: Option<Value>,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub updated_at: String,
    /// Returned once, on create (secret-based auth methods only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

impl From<Client> for ClientView {
    fn from(c: Client) -> Self {
        Self {
            client_id: c.client_id,
            name: c.name,
            client_type: c.client_type.into(),
            application_type: c.application_type.into(),
            auth_method: c.auth_method.into(),
            redirect_uris: c.redirect_uris,
            grant_types: map_vec(&c.grant_types),
            scopes: c.scopes,
            require_pkce: c.require_pkce,
            jwks: c.jwks.as_deref().and_then(|j| serde_json::from_str(j).ok()),
            created_at: ts(c.created_at),
            updated_at: ts(c.updated_at),
            client_secret: None,
        }
    }
}

/// One page of clients.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientList {
    pub items: Vec<ClientView>,
    /// Present if and only if more items follow.
    pub next_cursor: Option<Uuid>,
}

impl From<Page<Client>> for ClientList {
    fn from(p: Page<Client>) -> Self {
        Self {
            items: p.items.into_iter().map(Into::into).collect(),
            next_cursor: p.next_cursor,
        }
    }
}

/// The new secret returned by `POST …/clients/{client_id}/secret`. The previous secret stops
/// working immediately.
#[derive(Serialize, ToSchema)]
pub struct ClientSecretView {
    pub client_id: String,
    pub client_secret: String,
}

impl std::fmt::Debug for ClientSecretView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSecretView")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

fn default_application_type() -> ApplicationType {
    ApplicationType::Web
}

fn default_grant_types() -> Vec<GrantType> {
    vec![GrantType::AuthorizationCode]
}

/// Body of `POST /tenants/{slug}/clients`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateClient {
    pub name: String,
    pub client_type: ClientType,
    /// Default `web`.
    #[serde(default = "default_application_type")]
    pub application_type: ApplicationType,
    /// Default `none` for public clients, `client_secret_basic` for confidential clients.
    #[serde(default)]
    pub auth_method: Option<ClientAuthMethod>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// Default `["authorization_code"]`.
    #[serde(default = "default_grant_types")]
    pub grant_types: Vec<GrantType>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Default `true`. Only confidential clients may set `false`.
    #[serde(default)]
    pub require_pkce: Option<bool>,
    /// Inline public JWK Set, required for `private_key_jwt`.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub jwks: Option<Value>,
    /// Not supported in this release (rejected with 422).
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

impl From<CreateClient> for ClientInput {
    fn from(c: CreateClient) -> Self {
        let auth_method = c.auth_method.unwrap_or(match c.client_type {
            ClientType::Public => ClientAuthMethod::None,
            ClientType::Confidential => ClientAuthMethod::ClientSecretBasic,
        });
        Self {
            name: c.name,
            client_type: c.client_type.into(),
            application_type: c.application_type.into(),
            auth_method: auth_method.into(),
            redirect_uris: c.redirect_uris,
            grant_types: map_vec(&c.grant_types),
            scopes: c.scopes,
            require_pkce: c.require_pkce,
            jwks: c.jwks.map(|j| j.to_string()),
            jwks_uri: c.jwks_uri,
        }
    }
}

/// Body of `PATCH …/clients/{client_id}`. Client type, application type and auth method are
/// fixed at creation. `jwks: null` clears the JWK Set.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateClient {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub grant_types: Option<Vec<GrantType>>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub require_pkce: Option<bool>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<Object>)]
    pub jwks: Option<Option<Value>>,
}

impl From<UpdateClient> for ClientPatch {
    fn from(u: UpdateClient) -> Self {
        Self {
            name: u.name,
            redirect_uris: u.redirect_uris,
            grant_types: u.grant_types.as_deref().map(map_vec),
            scopes: u.scopes,
            require_pkce: u.require_pkce,
            jwks: u.jwks.map(|j| j.map(|v| v.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------------------------

/// OIDC Core §5.1.1 address claim.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Address {
    pub formatted: Option<String>,
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

impl From<CoreAddress> for Address {
    fn from(a: CoreAddress) -> Self {
        let CoreAddress {
            formatted,
            street_address,
            locality,
            region,
            postal_code,
            country,
        } = a;
        Self {
            formatted,
            street_address,
            locality,
            region,
            postal_code,
            country,
        }
    }
}

impl From<Address> for CoreAddress {
    fn from(a: Address) -> Self {
        let Address {
            formatted,
            street_address,
            locality,
            region,
            postal_code,
            country,
        } = a;
        Self {
            formatted,
            street_address,
            locality,
            region,
            postal_code,
            country,
        }
    }
}

/// OIDC Core §5.1 standard claims other than `sub`, `email` and `email_verified`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct StandardClaims {
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub preferred_username: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
    pub address: Option<Address>,
}

/// Generates both conversions between the wire and domain claims (identical field sets).
macro_rules! claims_conversions {
    ($($field:ident),+ ; $($mapped:ident),+) => {
        impl From<CoreStandardClaims> for StandardClaims {
            fn from(c: CoreStandardClaims) -> Self {
                Self {
                    $($field: c.$field,)+
                    $($mapped: c.$mapped.map(Into::into),)+
                }
            }
        }

        impl From<StandardClaims> for CoreStandardClaims {
            fn from(c: StandardClaims) -> Self {
                Self {
                    $($field: c.$field,)+
                    $($mapped: c.$mapped.map(Into::into),)+
                }
            }
        }
    };
}

claims_conversions!(
    name, given_name, family_name, middle_name, nickname, preferred_username, profile, picture,
    website, gender, birthdate, zoneinfo, locale, phone_number, phone_number_verified;
    address
);

/// A user. Password data is never returned.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserView {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub username: Option<String>,
    pub claims: StandardClaims,
    pub status: UserStatus,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub updated_at: String,
    #[schema(format = DateTime)]
    pub last_login_at: Option<String>,
}

impl From<User> for UserView {
    fn from(u: User) -> Self {
        Self {
            id: u.id.0,
            email: u.email,
            email_verified: u.email_verified,
            username: u.username,
            claims: u.claims.into(),
            status: u.status.into(),
            created_at: ts(u.created_at),
            updated_at: ts(u.updated_at),
            last_login_at: u.last_login_at.map(ts),
        }
    }
}

/// One page of users.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserList {
    pub items: Vec<UserView>,
    /// Present if and only if more items follow.
    pub next_cursor: Option<Uuid>,
}

impl From<Page<User>> for UserList {
    fn from(p: Page<User>) -> Self {
        Self {
            items: p.items.into_iter().map(Into::into).collect(),
            next_cursor: p.next_cursor,
        }
    }
}

/// Body of `POST /tenants/{slug}/users`. Set exactly one of `password` and `invite: true`; an
/// invitation emails a single-use link (valid 7 days) for the user to choose a password.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateUser {
    pub email: String,
    #[serde(default)]
    #[schema(format = Password)]
    pub password: Option<String>,
    #[serde(default)]
    pub invite: bool,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub claims: StandardClaims,
}

impl std::fmt::Debug for CreateUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateUser")
            .field("email", &self.email)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("invite", &self.invite)
            .field("email_verified", &self.email_verified)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl From<CreateUser> for UserInput {
    fn from(c: CreateUser) -> Self {
        Self {
            email: c.email,
            password: c.password.map(SecretString::from),
            invite: c.invite,
            email_verified: c.email_verified,
            username: c.username,
            claims: c.claims.into(),
        }
    }
}

/// Body of `PATCH …/users/{user_id}`. `username: null` clears the username; `status: blocked`
/// blocks sign-in.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateUser {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub username: Option<Option<String>>,
    #[serde(default)]
    pub claims: Option<StandardClaims>,
    #[serde(default)]
    pub status: Option<UserStatus>,
}

impl From<UpdateUser> for UserPatch {
    fn from(u: UpdateUser) -> Self {
        Self {
            email: u.email,
            email_verified: u.email_verified,
            username: u.username,
            claims: u.claims.map(Into::into),
            status: u.status.map(Into::into),
        }
    }
}
