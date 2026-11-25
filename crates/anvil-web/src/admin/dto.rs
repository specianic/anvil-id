//! Wire types of the management API (JSON, snake_case) and their conversions to and from the
//! domain types. anvil-core stays free of OpenAPI concerns, so every type that appears in the
//! spec is defined here; the enums mirror the domain enums one to one.

use anvil_core::model::{
    ActorKind as CoreActorKind, Address as CoreAddress, ApplicationType as CoreApplicationType,
    AuditAction as CoreAuditAction, AuditEvent, AuditOutcome as CoreAuditOutcome,
    CaptchaProvider as CoreCaptchaProvider, Client, ClientAuthMethod as CoreClientAuthMethod,
    ClientType as CoreClientType, ConsentMode as CoreConsentMode,
    CredentialKind as CoreCredentialKind, CredentialSummary, DEFAULT_SIGNING_ALG,
    EmailKind as CoreEmailKind, GrantType as CoreGrantType, Page,
    RegistrationMode as CoreRegistrationMode, SmtpTls as CoreSmtpTls,
    StandardClaims as CoreStandardClaims, Tenant, TenantSettings as CoreTenantSettings,
    TokenFormat as CoreTokenFormat, User, UserStatus as CoreUserStatus,
};
use anvil_core::service::client::{ClientInput, ClientOptions, ClientOptionsPatch, ClientPatch};
use anvil_core::service::mail_settings::{SmtpInput, SmtpView as CoreSmtpView, TemplateInput};
use anvil_core::service::session::SessionInfo;
use anvil_core::service::tenant::{
    CaptchaChange, CaptchaInput as CoreCaptchaInput, NewTenantInput, TenantPatch,
};
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
wire_enum!(
    /// Format of the access tokens issued to a client.
    TokenFormat => CoreTokenFormat { Jwt, Opaque }
);
wire_enum!(
    /// When the consent screen is shown: `required` asks for every scope not granted yet;
    /// `skip_first_party` never asks (first-party clients only).
    ConsentMode => CoreConsentMode { Required, SkipFirstParty }
);
wire_enum!(
    /// CAPTCHA provider.
    CaptchaProvider => CoreCaptchaProvider { Turnstile, Hcaptcha }
);
wire_enum!(
    /// Kind of a user credential.
    CredentialKind => CoreCredentialKind { Password, Webauthn, Totp }
);
wire_enum!(
    /// Who performed an audited action.
    ActorKind => CoreActorKind { User, Client, Admin, System }
);
wire_enum!(
    /// Whether an audited action succeeded.
    AuditOutcome => CoreAuditOutcome { Success, Failure }
);
wire_enum!(
    /// An audited action.
    AuditAction => CoreAuditAction {
        LoginSucceeded,
        LoginFailed,
        SecondFactorFailed,
        PasskeyRegistered,
        PasskeyRemoved,
        PasskeyCloneSuspected,
        TotpEnrolled,
        TotpRemoved,
        RecoveryCodeUsed,
        RecoveryCodesRegenerated,
        PasswordChanged,
        UserRegistered,
        EmailVerified,
        ConsentGranted,
        ConsentRevoked,
        SessionRevoked,
        SessionsRevokedAll,
        TokenRevoked,
        RefreshReuseDetected,
        CodeReuseDetected,
        KeyGenerated,
        KeyActivated,
        KeyRetired,
        KeyRotationRequested,
        RateLimitLockout,
        CaptchaFailed,
        UserCreated,
        UserUpdated,
        UserDeleted,
        ClientCreated,
        ClientUpdated,
        ClientDeleted,
        ClientSecretRotated,
        TenantCreated,
        TenantUpdated,
        TenantDeleted,
        EmailTemplateUpdated,
        EmailTemplateReset,
        SmtpSettingsUpdated,
        SmtpTestSent,
        AdminSetupCompleted,
    }
);
wire_enum!(
    /// Kind of a transactional email.
    EmailKind => CoreEmailKind {
        Verification,
        Recovery,
        Invitation,
        PasswordChanged,
        RecoveryCodeUsed,
    }
);
wire_enum!(
    /// SMTP transport security.
    SmtpTls => CoreSmtpTls { Starttls, Implicit, None }
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
    /// Line of the failing template part (email template validation only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
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

/// Per-tenant settings as returned by the API. The CAPTCHA secret is never returned.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TenantSettings {
    pub registration: RegistrationMode,
    /// Users must verify their email address before they can sign in.
    pub require_verified_email: bool,
    /// Enabled ID-token signing algorithms (`RS256`, `ES256`, `Ed25519`); RS256 is always first.
    pub signing_algs: Vec<String>,
    /// CAPTCHA on registration and after repeated failed sign-ins; `null` = disabled.
    pub captcha: Option<CaptchaView>,
}

impl From<CoreTenantSettings> for TenantSettings {
    fn from(s: CoreTenantSettings) -> Self {
        Self {
            registration: s.registration.into(),
            require_verified_email: s.require_verified_email,
            signing_algs: s.effective_signing_algs(),
            captcha: s.captcha.map(|c| CaptchaView {
                provider: c.provider.into(),
                site_key: c.site_key,
                configured: true,
            }),
        }
    }
}

/// A tenant's CAPTCHA configuration (the secret is write-only).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CaptchaView {
    pub provider: CaptchaProvider,
    pub site_key: String,
    /// Always `true`: a secret is stored (sealed); it cannot be read back.
    pub configured: bool,
}

/// CAPTCHA configuration as written by an administrator. The secret is sealed before it is
/// stored and is never returned.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptchaInput {
    pub provider: CaptchaProvider,
    pub site_key: String,
    /// The provider's secret key (write-only).
    #[schema(format = Password)]
    pub secret: String,
}

impl std::fmt::Debug for CaptchaInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptchaInput")
            .field("provider", &self.provider)
            .field("site_key", &self.site_key)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl From<CaptchaInput> for CoreCaptchaInput {
    fn from(c: CaptchaInput) -> Self {
        Self {
            provider: c.provider.into(),
            site_key: c.site_key,
            secret: SecretString::from(c.secret),
        }
    }
}

/// Settings of a new tenant. Absent fields take their defaults; CAPTCHA is configured with
/// `PATCH` once the tenant exists.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NewTenantSettings {
    pub registration: RegistrationMode,
    pub require_verified_email: bool,
    /// Signing algorithms to enable besides RS256 (`ES256`, `Ed25519`).
    pub signing_algs: Vec<String>,
}

impl Default for NewTenantSettings {
    fn default() -> Self {
        let core = CoreTenantSettings::default();
        Self {
            registration: core.registration.into(),
            require_verified_email: core.require_verified_email,
            signing_algs: core.signing_algs,
        }
    }
}

impl From<NewTenantSettings> for CoreTenantSettings {
    fn from(s: NewTenantSettings) -> Self {
        Self {
            registration: s.registration.into(),
            require_verified_email: s.require_verified_email,
            signing_algs: s.signing_algs,
            captcha: None,
        }
    }
}

/// Partial settings update: absent fields keep their current value. `captcha: null` disables
/// CAPTCHA; an object enables or replaces it.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TenantSettingsPatch {
    #[serde(default)]
    pub registration: Option<RegistrationMode>,
    #[serde(default)]
    pub require_verified_email: Option<bool>,
    /// The complete list of enabled algorithms (RS256 is always kept). Disabling an algorithm
    /// that a client uses for its ID tokens is refused with 409.
    #[serde(default)]
    pub signing_algs: Option<Vec<String>>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<CaptchaInput>)]
    pub captcha: Option<Option<CaptchaInput>>,
}

impl TenantSettingsPatch {
    /// Splits the patch into the merged settings (current values for absent fields; `None`
    /// when no plain setting is present) and the CAPTCHA change.
    pub fn merge(
        self,
        current: &CoreTenantSettings,
    ) -> (Option<CoreTenantSettings>, Option<CaptchaChange>) {
        let captcha = self.captcha.map(|c| match c {
            Some(input) => CaptchaChange::Set(input.into()),
            None => CaptchaChange::Clear,
        });
        let touched = self.registration.is_some()
            || self.require_verified_email.is_some()
            || self.signing_algs.is_some();
        let settings = touched.then(|| CoreTenantSettings {
            registration: self.registration.map_or(current.registration, Into::into),
            require_verified_email: self
                .require_verified_email
                .unwrap_or(current.require_verified_email),
            signing_algs: self
                .signing_algs
                .unwrap_or_else(|| current.signing_algs.clone()),
            captcha: current.captcha.clone(),
        });
        (settings, captcha)
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
    pub settings: NewTenantSettings,
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
/// `settings` is merged with the current settings field by field.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateTenant {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub host: Option<Option<String>>,
    #[serde(default)]
    pub settings: Option<TenantSettingsPatch>,
}

impl UpdateTenant {
    /// The core patch and CAPTCHA change, with settings merged onto `current`.
    pub fn into_patch(self, current: &CoreTenantSettings) -> (TenantPatch, Option<CaptchaChange>) {
        let (settings, captcha) = match self.settings {
            Some(p) => p.merge(current),
            None => (None, None),
        };
        (
            TenantPatch {
                display_name: self.display_name,
                host: self.host,
                settings,
            },
            captcha,
        )
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
    pub token_format: TokenFormat,
    pub consent_mode: ConsentMode,
    /// ID-token signing algorithm (one of the tenant's `signing_algs`).
    pub id_token_signed_response_alg: String,
    /// May introspect any token of the tenant (confidential clients only).
    pub can_introspect: bool,
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
            token_format: c.token_format.into(),
            consent_mode: c.consent_mode.into(),
            id_token_signed_response_alg: c
                .id_token_signed_response_alg
                .unwrap_or_else(|| DEFAULT_SIGNING_ALG.to_owned()),
            can_introspect: c.can_introspect,
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
    /// Default `jwt`.
    #[serde(default)]
    pub token_format: Option<TokenFormat>,
    /// Default `required`.
    #[serde(default)]
    pub consent_mode: Option<ConsentMode>,
    /// Default `RS256`; must be enabled in the tenant's `signing_algs`.
    #[serde(default)]
    pub id_token_signed_response_alg: Option<String>,
    /// Default `false`; confidential clients only.
    #[serde(default)]
    pub can_introspect: Option<bool>,
}

impl CreateClient {
    /// The registration and the 0.2 options (secure defaults for absent fields).
    pub fn into_parts(self) -> (ClientInput, ClientOptions) {
        let defaults = ClientOptions::default();
        let options = ClientOptions {
            token_format: self.token_format.map_or(defaults.token_format, Into::into),
            consent_mode: self.consent_mode.map_or(defaults.consent_mode, Into::into),
            id_token_signed_response_alg: self
                .id_token_signed_response_alg
                .clone()
                .or(defaults.id_token_signed_response_alg),
            can_introspect: self.can_introspect.unwrap_or(defaults.can_introspect),
        };
        (self.into(), options)
    }
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
    #[serde(default)]
    pub token_format: Option<TokenFormat>,
    #[serde(default)]
    pub consent_mode: Option<ConsentMode>,
    /// `null` resets to RS256.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub id_token_signed_response_alg: Option<Option<String>>,
    #[serde(default)]
    pub can_introspect: Option<bool>,
}

impl UpdateClient {
    /// The registration patch and the options patch.
    pub fn into_parts(self) -> (ClientPatch, ClientOptionsPatch) {
        let options = ClientOptionsPatch {
            token_format: self.token_format.map(Into::into),
            consent_mode: self.consent_mode.map(Into::into),
            id_token_signed_response_alg: self.id_token_signed_response_alg,
            can_introspect: self.can_introspect,
        };
        let patch = ClientPatch {
            name: self.name,
            redirect_uris: self.redirect_uris,
            grant_types: self.grant_types.as_deref().map(map_vec),
            scopes: self.scopes,
            require_pkce: self.require_pkce,
            jwks: self.jwks.map(|j| j.map(|v| v.to_string())),
        };
        (patch, options)
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

// ---------------------------------------------------------------------------------------------
// Sessions and credentials
// ---------------------------------------------------------------------------------------------

/// An active browser session. The session token is never returned.
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionView {
    pub id: Uuid,
    pub user_id: Uuid,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub last_seen_at: String,
    #[schema(format = DateTime)]
    pub auth_time: String,
    /// Absolute expiry.
    #[schema(format = DateTime)]
    pub expires_at: String,
    /// Expiry if the session stays idle (refreshed by activity).
    #[schema(format = DateTime)]
    pub idle_expires_at: String,
    /// Client IP at sign-in.
    pub ip: Option<String>,
    /// User agent at sign-in.
    pub user_agent: Option<String>,
    pub acr: String,
    pub amr: Vec<String>,
}

impl From<SessionInfo> for SessionView {
    fn from(s: SessionInfo) -> Self {
        Self {
            id: s.id.0,
            user_id: s.user_id.0,
            created_at: ts(s.created_at),
            last_seen_at: ts(s.last_seen_at),
            auth_time: ts(s.auth_time),
            expires_at: ts(s.expires_at),
            idle_expires_at: ts(s.idle_expires_at),
            ip: s.ip,
            user_agent: s.user_agent,
            acr: s.acr,
            amr: s.amr,
        }
    }
}

/// A list of sessions (tenant lists are paged; a user's sessions come in one page).
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionList {
    pub items: Vec<SessionView>,
    /// Present if and only if more items follow.
    pub next_cursor: Option<Uuid>,
}

impl From<Page<SessionInfo>> for SessionList {
    fn from(p: Page<SessionInfo>) -> Self {
        Self {
            items: p.items.into_iter().map(Into::into).collect(),
            next_cursor: p.next_cursor,
        }
    }
}

impl From<Vec<SessionInfo>> for SessionList {
    fn from(v: Vec<SessionInfo>) -> Self {
        Self {
            items: v.into_iter().map(Into::into).collect(),
            next_cursor: None,
        }
    }
}

/// Result of revoking all sessions of a user.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokedSessions {
    /// Number of sessions revoked.
    pub revoked: u64,
}

/// A user credential (password, passkey or TOTP). Secrets, public keys and seeds are never
/// returned.
#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialView {
    pub id: Uuid,
    pub kind: CredentialKind,
    pub label: String,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub last_used_at: Option<String>,
}

impl From<CredentialSummary> for CredentialView {
    fn from(c: CredentialSummary) -> Self {
        Self {
            id: c.id.0,
            kind: c.kind.into(),
            label: c.label,
            created_at: ts(c.created_at),
            last_used_at: c.last_used_at.map(ts),
        }
    }
}

/// A user's credentials.
#[derive(Debug, Serialize, ToSchema)]
pub struct CredentialList {
    pub items: Vec<CredentialView>,
}

// ---------------------------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------------------------

/// Audit log query. All filters are optional and combined with AND; results are newest first.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct AuditQueryParams {
    /// Inclusive lower bound on the event time (RFC 3339).
    #[param(format = DateTime)]
    pub from: Option<String>,
    /// Exclusive upper bound on the event time (RFC 3339).
    #[param(format = DateTime)]
    pub to: Option<String>,
    /// Actor id (user id, client id or admin subject).
    pub actor: Option<String>,
    /// Action name, e.g. `login_failed`.
    #[param(value_type = Option<AuditAction>)]
    pub action: Option<String>,
    /// `success` or `failure`.
    #[param(value_type = Option<AuditOutcome>)]
    pub outcome: Option<String>,
    /// Target (user id, client id, session id, ...).
    pub target: Option<String>,
    /// Return events older than this event id (the previous page's `next_cursor`).
    pub cursor: Option<Uuid>,
    /// Page size, 1 to 200 (default 50).
    #[param(minimum = 1, maximum = 200)]
    pub limit: Option<u32>,
}

/// Who performed an audited action.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditActorView {
    pub kind: ActorKind,
    pub id: Option<String>,
}

/// One audit event.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEventView {
    pub id: Uuid,
    #[schema(format = DateTime)]
    pub at: String,
    pub actor: AuditActorView,
    pub action: AuditAction,
    pub target: Option<String>,
    pub outcome: AuditOutcome,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub trace_id: Option<String>,
    /// Typed details (identifiers, enum names, counts; never secrets).
    #[schema(value_type = Object)]
    pub details: Value,
}

impl From<AuditEvent> for AuditEventView {
    fn from(e: AuditEvent) -> Self {
        Self {
            id: e.id.0,
            at: ts(e.at),
            actor: AuditActorView {
                kind: e.actor.kind.into(),
                id: e.actor.id,
            },
            action: e.action.into(),
            target: e.target,
            outcome: e.outcome.into(),
            ip: e.ctx.ip.map(|ip| ip.to_string()),
            user_agent: e.ctx.user_agent,
            trace_id: e.ctx.trace_id,
            details: Value::Object(e.details.as_map().clone()),
        }
    }
}

/// One page of audit events.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEventList {
    pub items: Vec<AuditEventView>,
    /// Pass as `cursor` for the next (older) page; present if and only if more items follow.
    pub next_cursor: Option<Uuid>,
}

impl From<Page<AuditEvent>> for AuditEventList {
    fn from(p: Page<AuditEvent>) -> Self {
        Self {
            items: p.items.into_iter().map(Into::into).collect(),
            next_cursor: p.next_cursor,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Email templates and SMTP
// ---------------------------------------------------------------------------------------------

/// An email template: the tenant override (`customized: true`) or the theme default.
#[derive(Debug, Serialize, ToSchema)]
pub struct EmailTemplateView {
    pub kind: EmailKind,
    /// Whether the tenant overrides the theme default.
    pub customized: bool,
    pub subject: String,
    pub body_html: String,
    pub body_text: String,
    /// Variables the template may use.
    pub variables: Vec<String>,
    /// When the override was saved (`null` for the default).
    #[schema(format = DateTime)]
    pub updated_at: Option<String>,
}

/// Every email template of a tenant.
#[derive(Debug, Serialize, ToSchema)]
pub struct EmailTemplateList {
    pub items: Vec<EmailTemplateView>,
}

/// Body of `PUT …/email-templates/{kind}` (minijinja syntax; `.html` is autoescaped).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PutEmailTemplate {
    /// One line.
    pub subject: String,
    pub body_html: String,
    pub body_text: String,
}

impl From<PutEmailTemplate> for TemplateInput {
    fn from(p: PutEmailTemplate) -> Self {
        Self {
            subject: p.subject,
            body_html: p.body_html,
            body_text: p.body_text,
        }
    }
}

/// A tenant's SMTP settings. The password is never returned.
#[derive(Debug, Serialize, ToSchema)]
pub struct SmtpSettingsView {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    /// Whether a password is stored.
    pub password_set: bool,
    pub from: String,
    pub tls: SmtpTls,
    #[schema(format = DateTime)]
    pub updated_at: String,
}

impl From<CoreSmtpView> for SmtpSettingsView {
    fn from(v: CoreSmtpView) -> Self {
        Self {
            host: v.host,
            port: v.port,
            username: v.username,
            password_set: v.password_set,
            from: v.from,
            tls: v.tls.into(),
            updated_at: ts(v.updated_at),
        }
    }
}

fn default_tls() -> SmtpTls {
    SmtpTls::Starttls
}

/// Body of `PUT …/smtp`. An absent or empty `password` keeps the stored one.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PutSmtpSettings {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    /// Write-only.
    #[serde(default)]
    #[schema(format = Password)]
    pub password: Option<String>,
    /// `addr` or `Name <addr>`.
    pub from: String,
    /// Default `starttls`.
    #[serde(default = "default_tls")]
    pub tls: SmtpTls,
}

impl std::fmt::Debug for PutSmtpSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PutSmtpSettings")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("from", &self.from)
            .field("tls", &self.tls)
            .finish()
    }
}

impl From<PutSmtpSettings> for SmtpInput {
    fn from(p: PutSmtpSettings) -> Self {
        Self {
            host: p.host,
            port: p.port,
            username: p.username,
            password: p.password.map(SecretString::from),
            from: p.from,
            tls: p.tls.into(),
        }
    }
}

/// Body of `POST …/smtp/test`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SmtpTestRequest {
    /// Recipient of the test email.
    pub to: String,
}

/// Outcome of a test send. The call succeeds even when delivery fails.
#[derive(Debug, Serialize, ToSchema)]
pub struct SmtpTestResult {
    pub delivered: bool,
    /// The SMTP error (credentials redacted) when delivery failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
