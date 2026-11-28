//! Wire types of the management API (JSON, snake_case) and their conversions to and from the
//! domain types. anvil-core stays free of OpenAPI concerns, so every type that appears in the
//! spec is defined here; the enums mirror the domain enums one to one.

use anvil_core::model::{
    ActorKind as CoreActorKind, Address as CoreAddress, AppleConfig as CoreAppleConfig,
    ApplicationType as CoreApplicationType, AuditAction as CoreAuditAction, AuditEvent,
    AuditOutcome as CoreAuditOutcome, CaptchaProvider as CoreCaptchaProvider,
    CimdPolicy as CoreCimdPolicy, CimdSettings as CoreCimdSettings,
    ClaimMapping as CoreClaimMapping, Client, ClientAuthMethod as CoreClientAuthMethod,
    ClientKind as CoreClientKind, ClientSource as CoreClientSource, ClientType as CoreClientType,
    Connection, ConnectionConfig as CoreConnectionConfig, ConnectionKind as CoreConnectionKind,
    ConsentMode as CoreConsentMode, CredentialKind as CoreCredentialKind, CredentialSummary,
    DEFAULT_SIGNING_ALG, DcrPolicy as CoreDcrPolicy, DcrSettings as CoreDcrSettings,
    EmailKind as CoreEmailKind, EndpointOverrides as CoreEndpointOverrides,
    GrantType as CoreGrantType, HeadlessSettings as CoreHeadlessSettings, IdpMetadata,
    KeyState as CoreKeyState, MfaPolicy as CoreMfaPolicy, NameIdFormat as CoreNameIdFormat,
    OAuth2Config as CoreOAuth2Config, OidcConfig as CoreOidcConfig,
    OrgClientPolicy as CoreOrgClientPolicy, Page, ParSettings as CoreParSettings,
    RegistrationMode as CoreRegistrationMode, SamlAttributeMapping as CoreSamlAttributeMapping,
    SamlConfig as CoreSamlConfig, SigningKey as CoreSigningKey, SmtpTls as CoreSmtpTls,
    SocialConfig as CoreSocialConfig, SocialProvider as CoreSocialProvider,
    StandardClaims as CoreStandardClaims, Tenant, TenantSettings as CoreTenantSettings,
    TokenFormat as CoreTokenFormat, User, UserStatus as CoreUserStatus,
};
use anvil_core::service::client::{ClientInput, ClientOptions, ClientOptionsPatch, ClientPatch};
use anvil_core::service::connection::{ConnectionPatch, NewConnectionInput};
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

use super::tenants::{TokenClaimMapping, TokenClaimMappingPatch};

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
    /// Organization policy of a client: `off` (no org claims; the `organization` authorization
    /// parameter is refused), `optional` (an org is selected when the user belongs to one) or
    /// `required` (every authorization needs an org).
    OrgClientPolicy => CoreOrgClientPolicy { Off, Optional, Required }
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
    /// What a client is: `application` (default) or `agent`, an AI agent acting for the user
    /// (the consent page says so). An agent never skips consent. Administrators set it on any
    /// client; dynamic registration and metadata documents never do.
    ClientKind => CoreClientKind { Application, Agent }
);
wire_enum!(
    /// CAPTCHA provider.
    CaptchaProvider => CoreCaptchaProvider { Turnstile, Hcaptcha }
);
wire_enum!(
    /// Dynamic client registration policy: `disabled` (no `/register`), `allow_listed` (an
    /// initial access token is required; optional redirect-host allow-list) or `open`.
    DcrPolicy => CoreDcrPolicy { Disabled, AllowListed, Open }
);
wire_enum!(
    /// Client ID Metadata Document policy: `disabled` (URL client ids are unknown clients),
    /// `allow_listed` (documents on `allowed_hosts` only) or `open` (any https host passing the
    /// outbound policy).
    CimdPolicy => CoreCimdPolicy { Disabled, AllowListed, Open }
);
wire_enum!(
    /// How a client came to exist: `static` (administrator), `dynamic` (RFC 7591 registration)
    /// or `cimd` (materialised from a Client ID Metadata Document; the client id is its URL).
    ClientSource => CoreClientSource { Static, Dynamic, Cimd }
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
        IdentityLinked,
        IdentityUnlinked,
        UpstreamLoginFailed,
        ConnectionCreated,
        ConnectionUpdated,
        ConnectionDeleted,
        ConnectionSecretRotated,
        BrandingUpdated,
        Logout,
        BackchannelLogoutFailed,
        EmailChangeRequested,
        EmailChanged,
        ProfileUpdated,
        StepUpCompleted,
        EmailCodeSent,
        RoleCreated,
        RoleUpdated,
        RoleDeleted,
        RoleAssigned,
        RoleUnassigned,
        AttributeDefined,
        AttributeDeleted,
        UserAttributesUpdated,
        WebhookEndpointCreated,
        WebhookEndpointUpdated,
        WebhookEndpointDeleted,
        WebhookSecretRotated,
        WebhookEndpointDisabled,
        WebhookDeliveryFailed,
        WebhookTestSent,
        WebhookRedelivered,
        ClientRegistered,
        ClientRegistrationUpdated,
        ClientRegistrationDeleted,
        CimdClientRefreshed,
        InitialAccessTokenCreated,
        InitialAccessTokenRevoked,
        TenantConfigApplied,
        AdminRecoveryIssued,
        OrganizationCreated,
        OrganizationUpdated,
        OrganizationDeleted,
        OrgMemberAdded,
        OrgMemberRemoved,
        OrgRoleAssigned,
        OrgRoleUnassigned,
        OrgInvitationCreated,
        OrgInvitationRevoked,
        OrgInvitationAccepted,
        OrgDomainCreated,
        OrgDomainVerified,
        OrgDomainVerificationFailed,
        OrgDomainUnverified,
        OrgDomainUpdated,
        OrgDomainDeleted,
        SamlLoginSucceeded,
        SamlLoginFailed,
        UsersImported,
        UserExported,
        PasswordProfileCreated,
        PasswordProfileDeleted,
        UserRecoverySent,
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
        LoginCode,
        EmailChange,
        EmailChanged,
        OrgInvitation,
    }
);
wire_enum!(
    /// SMTP transport security.
    SmtpTls => CoreSmtpTls { Starttls, Implicit, None }
);
wire_enum!(
    /// Whether sign-in needs a second factor: `off`, `optional` (users who enrolled one) or
    /// `required` (users without one enrol first). Across tenant and client the strictest wins.
    MfaPolicy => CoreMfaPolicy { Off, Optional, Required }
);
wire_enum!(
    /// Social provider preset of a connection.
    SocialProvider => CoreSocialProvider { Google, Apple, Microsoft, Github }
);
wire_enum!(
    /// Kind of an upstream connection (derived from its config).
    ConnectionKind => CoreConnectionKind { Google, Apple, Microsoft, Github, Oidc, Oauth2, Saml }
);

/// RFC 3339 timestamp. The domain only holds times inside years 0..=9999, which always format.
pub(super) fn ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// Deserialises a present field (including `null`) as `Some(..)`, so PATCH bodies can tell
/// "absent" (leave unchanged) from `null` (clear).
pub(super) fn double_option<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
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

/// Query of `GET /tenants/{slug}/users`: cursor pagination, or a lookup by email address.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct UserListQuery {
    /// Return items after this id (the previous page's `next_cursor`). Not allowed with `email`.
    pub after: Option<Uuid>,
    /// Page size, 1 to 200 (default 50).
    #[param(minimum = 1, maximum = 200)]
    pub limit: Option<u32>,
    /// Exact address, case-insensitive (trimmed and lowercased before comparing); returns at most
    /// one user and no `next_cursor`. A malformed address is a 422 on `email`.
    pub email: Option<String>,
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
    /// Tenant MFA policy (a client may make it stricter).
    pub mfa_policy: MfaPolicy,
    /// Sign-in with a one-time code sent by email.
    pub email_otp: bool,
    /// Sign-in with a magic link sent by email.
    pub magic_link: bool,
    /// Link an upstream identity automatically when it asserts a trusted, verified email equal
    /// to an existing account's verified email.
    pub auto_link: bool,
    /// Whether upstream sign-in may create accounts; `null` follows `registration`.
    pub upstream_registration: Option<bool>,
    /// Page language when neither `ui_locales` nor `Accept-Language` matches.
    pub default_locale: String,
    /// Mapping of roles and permissions into tokens.
    pub claims: TokenClaimMapping,
    /// Dynamic client registration policy in force (always `disabled` for `system`).
    pub dcr: DcrSettings,
    /// Client ID Metadata Document policy in force (always `disabled` for `system`).
    pub cimd: CimdSettings,
    /// Pushed authorization request policy (RFC 9126).
    pub par: ParSettings,
    /// Headless flow API settings (browser-mode origin allow-list).
    pub headless: HeadlessSettings,
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
            mfa_policy: s.mfa_policy.into(),
            email_otp: s.email_otp,
            magic_link: s.magic_link,
            auto_link: s.auto_link,
            upstream_registration: s.upstream_registration,
            default_locale: s.default_locale,
            claims: s.claims.into(),
            dcr: s.dcr.into(),
            cimd: s.cimd.into(),
            par: s.par.into(),
            headless: s.headless.into(),
        }
    }
}

/// Pushed authorization request policy of a tenant (RFC 9126).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ParSettings {
    /// Every client of the tenant must use pushed authorization requests (RFC 9126 §5
    /// `require_pushed_authorization_requests`). Default `false`; a client can still require it
    /// for itself.
    pub require_pushed_authorization_requests: bool,
}

impl From<CoreParSettings> for ParSettings {
    fn from(p: CoreParSettings) -> Self {
        Self {
            require_pushed_authorization_requests: p.require_pushed_authorization_requests,
        }
    }
}

impl From<ParSettings> for CoreParSettings {
    fn from(p: ParSettings) -> Self {
        Self {
            require_pushed_authorization_requests: p.require_pushed_authorization_requests,
        }
    }
}

/// Headless flow API settings of a tenant.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HeadlessSettings {
    /// Origins of single-page apps that may call the headless flow API with credentials
    /// (browser mode). Exact `https://host[:port]` origins, lowercase, no path or wildcard;
    /// `http://localhost` and `http://127.0.0.1` only in development mode. The app must be
    /// same-site with the issuer (browsers block cross-site cookies). Empty = only the
    /// tenant's own origin. At most 50.
    pub allowed_origins: Vec<String>,
}

impl From<CoreHeadlessSettings> for HeadlessSettings {
    fn from(h: CoreHeadlessSettings) -> Self {
        Self {
            allowed_origins: h.allowed_origins,
        }
    }
}

impl From<HeadlessSettings> for CoreHeadlessSettings {
    fn from(h: HeadlessSettings) -> Self {
        Self {
            allowed_origins: h.allowed_origins,
        }
    }
}

/// Dynamic client registration settings (RFC 7591).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct DcrSettings {
    /// Default `disabled`; `system` is always `disabled`.
    pub policy: DcrPolicy,
    /// Redirect-URI hosts accepted under `allow_listed` (host names or IP literals, no port);
    /// empty = any host allowed by the redirect URI rules.
    pub allowed_redirect_hosts: Vec<String>,
    /// Scopes a registered client may request; empty = `openid profile email address phone`.
    /// Admin API scopes are refused.
    pub allowed_scopes: Vec<String>,
    /// RFC 8707 resource indicators registered (and CIMD) clients may be granted.
    pub allowed_resources: Vec<String>,
    /// Registered confidential clients may use `client_credentials`.
    pub allow_client_credentials: bool,
    /// Most dynamically registered clients the tenant may hold (default 1000; soft cap).
    pub max_clients: u32,
}

impl Default for DcrSettings {
    fn default() -> Self {
        CoreDcrSettings::default().into()
    }
}

impl From<CoreDcrSettings> for DcrSettings {
    fn from(d: CoreDcrSettings) -> Self {
        Self {
            policy: d.policy.into(),
            allowed_redirect_hosts: d.allowed_redirect_hosts,
            allowed_scopes: d.allowed_scopes,
            allowed_resources: d.allowed_resources,
            allow_client_credentials: d.allow_client_credentials,
            max_clients: d.max_clients,
        }
    }
}

impl From<DcrSettings> for CoreDcrSettings {
    fn from(d: DcrSettings) -> Self {
        Self {
            policy: d.policy.into(),
            allowed_redirect_hosts: d.allowed_redirect_hosts,
            allowed_scopes: d.allowed_scopes,
            allowed_resources: d.allowed_resources,
            allow_client_credentials: d.allow_client_credentials,
            max_clients: d.max_clients,
        }
    }
}

/// Client ID Metadata Document settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CimdSettings {
    /// Default `disabled`; `system` is always `disabled`. Blocking a document URL is done with
    /// `allow_listed` (only the listed hosts are fetched).
    pub policy: CimdPolicy,
    /// Hosts whose documents are accepted under `allow_listed` (at least one); host names or IP
    /// literals, no port.
    pub allowed_hosts: Vec<String>,
    /// A document's `Cache-Control: max-age` is clamped to `min_cache_secs..=max_cache_secs`
    /// (60 to 604800 seconds; default 300 and 86400).
    pub min_cache_secs: u32,
    pub max_cache_secs: u32,
}

impl Default for CimdSettings {
    fn default() -> Self {
        CoreCimdSettings::default().into()
    }
}

impl From<CoreCimdSettings> for CimdSettings {
    fn from(c: CoreCimdSettings) -> Self {
        Self {
            policy: c.policy.into(),
            allowed_hosts: c.allowed_hosts,
            min_cache_secs: c.min_cache_secs,
            max_cache_secs: c.max_cache_secs,
        }
    }
}

impl From<CimdSettings> for CoreCimdSettings {
    fn from(c: CimdSettings) -> Self {
        Self {
            policy: c.policy.into(),
            allowed_hosts: c.allowed_hosts,
            min_cache_secs: c.min_cache_secs,
            max_cache_secs: c.max_cache_secs,
        }
    }
}

/// Partial DCR settings update: absent fields keep their current value; lists replace the
/// whole list.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DcrSettingsPatch {
    #[serde(default)]
    pub policy: Option<DcrPolicy>,
    #[serde(default)]
    pub allowed_redirect_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_scopes: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_resources: Option<Vec<String>>,
    #[serde(default)]
    pub allow_client_credentials: Option<bool>,
    #[serde(default)]
    pub max_clients: Option<u32>,
}

impl DcrSettingsPatch {
    /// The settings after this patch.
    pub fn merge(self, current: &CoreDcrSettings) -> CoreDcrSettings {
        CoreDcrSettings {
            policy: self.policy.map_or(current.policy, Into::into),
            allowed_redirect_hosts: self
                .allowed_redirect_hosts
                .unwrap_or_else(|| current.allowed_redirect_hosts.clone()),
            allowed_scopes: self
                .allowed_scopes
                .unwrap_or_else(|| current.allowed_scopes.clone()),
            allowed_resources: self
                .allowed_resources
                .unwrap_or_else(|| current.allowed_resources.clone()),
            allow_client_credentials: self
                .allow_client_credentials
                .unwrap_or(current.allow_client_credentials),
            max_clients: self.max_clients.unwrap_or(current.max_clients),
        }
    }
}

/// Partial CIMD settings update: absent fields keep their current value; `allowed_hosts`
/// replaces the whole list.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CimdSettingsPatch {
    #[serde(default)]
    pub policy: Option<CimdPolicy>,
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
    #[serde(default)]
    pub min_cache_secs: Option<u32>,
    #[serde(default)]
    pub max_cache_secs: Option<u32>,
}

impl CimdSettingsPatch {
    /// The settings after this patch.
    pub fn merge(self, current: &CoreCimdSettings) -> CoreCimdSettings {
        CoreCimdSettings {
            policy: self.policy.map_or(current.policy, Into::into),
            allowed_hosts: self
                .allowed_hosts
                .unwrap_or_else(|| current.allowed_hosts.clone()),
            min_cache_secs: self.min_cache_secs.unwrap_or(current.min_cache_secs),
            max_cache_secs: self.max_cache_secs.unwrap_or(current.max_cache_secs),
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
    /// Default `optional`.
    pub mfa_policy: MfaPolicy,
    /// Default `false`; needs SMTP (the installation's, for a new tenant).
    pub email_otp: bool,
    /// Default `false`; needs SMTP (the installation's, for a new tenant).
    pub magic_link: bool,
    /// Default `true`.
    pub auto_link: bool,
    /// Default `null` (follow `registration`).
    pub upstream_registration: Option<bool>,
    /// Default `en`; a language tag such as `de` or `pt-BR`.
    pub default_locale: String,
    /// Default: `roles` gated by scope `roles`, `permissions` in the access token.
    pub claims: TokenClaimMapping,
    /// Default: disabled.
    pub dcr: DcrSettings,
    /// Default: disabled.
    pub cimd: CimdSettings,
    /// Default: pushed authorization requests optional.
    pub par: ParSettings,
    /// Default: no extra origins.
    pub headless: HeadlessSettings,
}

impl Default for NewTenantSettings {
    fn default() -> Self {
        let core = CoreTenantSettings::default();
        Self {
            registration: core.registration.into(),
            require_verified_email: core.require_verified_email,
            signing_algs: core.signing_algs,
            mfa_policy: core.mfa_policy.into(),
            email_otp: core.email_otp,
            magic_link: core.magic_link,
            auto_link: core.auto_link,
            upstream_registration: core.upstream_registration,
            default_locale: core.default_locale,
            claims: core.claims.into(),
            dcr: core.dcr.into(),
            cimd: core.cimd.into(),
            par: core.par.into(),
            headless: core.headless.into(),
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
            mfa_policy: s.mfa_policy.into(),
            email_otp: s.email_otp,
            magic_link: s.magic_link,
            auto_link: s.auto_link,
            upstream_registration: s.upstream_registration,
            default_locale: s.default_locale,
            cimd: s.cimd.into(),
            claims: s.claims.into(),
            dcr: s.dcr.into(),
            par: s.par.into(),
            headless: s.headless.into(),
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
    #[serde(default)]
    pub mfa_policy: Option<MfaPolicy>,
    /// Turning it on needs SMTP (tenant SMTP settings or the installation SMTP).
    #[serde(default)]
    pub email_otp: Option<bool>,
    /// Turning it on needs SMTP (tenant SMTP settings or the installation SMTP).
    #[serde(default)]
    pub magic_link: Option<bool>,
    #[serde(default)]
    pub auto_link: Option<bool>,
    /// `null` follows `registration`.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<bool>)]
    pub upstream_registration: Option<Option<bool>>,
    #[serde(default)]
    pub default_locale: Option<String>,
    /// Absent rules stay unchanged; `null` disables a rule. Claim names that collide with
    /// protocol or standard claims are refused (422).
    #[serde(default)]
    pub claims: Option<TokenClaimMappingPatch>,
    /// Absent fields stay unchanged. The system tenant refuses any policy but `disabled` (422).
    #[serde(default)]
    pub dcr: Option<DcrSettingsPatch>,
    /// Absent fields stay unchanged. The system tenant refuses any policy but `disabled` (422).
    #[serde(default)]
    pub cimd: Option<CimdSettingsPatch>,
    /// Replaces the PAR policy.
    #[serde(default)]
    pub par: Option<ParSettings>,
    /// Replaces the headless settings (the whole origin list). Wildcards, paths and non-https
    /// origins are refused (422).
    #[serde(default)]
    pub headless: Option<HeadlessSettings>,
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
            || self.signing_algs.is_some()
            || self.mfa_policy.is_some()
            || self.email_otp.is_some()
            || self.magic_link.is_some()
            || self.auto_link.is_some()
            || self.upstream_registration.is_some()
            || self.default_locale.is_some()
            || self.claims.is_some()
            || self.dcr.is_some()
            || self.cimd.is_some()
            || self.par.is_some()
            || self.headless.is_some();
        let settings = touched.then(|| CoreTenantSettings {
            registration: self.registration.map_or(current.registration, Into::into),
            require_verified_email: self
                .require_verified_email
                .unwrap_or(current.require_verified_email),
            signing_algs: self
                .signing_algs
                .unwrap_or_else(|| current.signing_algs.clone()),
            captcha: current.captcha.clone(),
            mfa_policy: self.mfa_policy.map_or(current.mfa_policy, Into::into),
            email_otp: self.email_otp.unwrap_or(current.email_otp),
            magic_link: self.magic_link.unwrap_or(current.magic_link),
            auto_link: self.auto_link.unwrap_or(current.auto_link),
            upstream_registration: self
                .upstream_registration
                .unwrap_or(current.upstream_registration),
            default_locale: self
                .default_locale
                .unwrap_or_else(|| current.default_locale.clone()),
            dcr: match self.dcr {
                Some(patch) => patch.merge(&current.dcr),
                None => current.dcr.clone(),
            },
            cimd: match self.cimd {
                Some(patch) => patch.merge(&current.cimd),
                None => current.cimd.clone(),
            },
            claims: match self.claims {
                Some(patch) => patch.merge(&current.claims),
                None => current.claims.clone(),
            },
            par: self.par.map_or_else(|| current.par.clone(), Into::into),
            headless: self
                .headless
                .map_or_else(|| current.headless.clone(), Into::into),
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
    /// The tenant's canonical issuer, computed by the server: `{scheme}://{host}` for a custom
    /// host, the public URL for `default`, else `{public_url}/t/{slug}`.
    pub issuer: String,
    /// The OpenID Provider configuration document of [`Self::issuer`].
    pub discovery_url: String,
    pub settings: TenantSettings,
    /// Optional capabilities available in this tenant (set by the operator, read-only).
    pub features: TenantFeatures,
    #[schema(format = DateTime)]
    pub created_at: String,
}

/// Optional capabilities of a tenant, decided by the operator's configuration.
#[derive(Debug, Clone, Copy, Default, Serialize, ToSchema)]
pub struct TenantFeatures {
    /// SAML 2.0 organization connections can be configured (operator flag `saml_experimental`;
    /// experimental through 1.0). Never in the system tenant, which has no organizations.
    pub saml: bool,
}

impl TenantFeatures {
    /// The features of `tenant` when the operator flag `saml_experimental` is `saml_flag`.
    pub fn of(tenant: &Tenant, saml_flag: bool) -> Self {
        Self {
            saml: saml_flag && tenant.slug != anvil_core::model::SYSTEM_TENANT_SLUG,
        }
    }
}

impl TenantView {
    /// The view of `t`, whose canonical issuer is `issuer`. DCR/CIMD settings show the policy
    /// in force (always `disabled` for the system tenant). `saml_flag` is the operator flag
    /// `saml_experimental`.
    pub fn new(t: Tenant, issuer: String, saml_flag: bool) -> Self {
        let features = TenantFeatures::of(&t, saml_flag);
        let dcr = t.effective_dcr();
        let cimd = t.effective_cimd();
        let mut settings = TenantSettings::from(t.settings);
        settings.dcr = dcr.into();
        settings.cimd = cimd.into();
        Self {
            id: t.id.0,
            slug: t.slug,
            display_name: t.display_name,
            host: t.host,
            discovery_url: format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            ),
            issuer,
            settings,
            features,
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

impl TenantList {
    /// The page `p`, each tenant with its canonical issuer from `issuer_of` (`saml_flag`: the
    /// operator flag `saml_experimental`).
    pub fn new(p: Page<Tenant>, issuer_of: impl Fn(&Tenant) -> String, saml_flag: bool) -> Self {
        Self {
            items: p
                .items
                .into_iter()
                .map(|t| {
                    let issuer = issuer_of(&t);
                    TenantView::new(t, issuer, saml_flag)
                })
                .collect(),
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

impl CreateTenant {
    /// The core input; `installation_smtp` = whether the installation SMTP is configured,
    /// `dev_mode` = whether the server runs in development mode.
    pub fn into_input(self, installation_smtp: bool, dev_mode: bool) -> NewTenantInput {
        NewTenantInput {
            slug: self.slug,
            display_name: self.display_name,
            host: self.host,
            settings: self.settings.into(),
            installation_smtp,
            dev_mode,
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
    /// `installation_smtp` = whether the installation SMTP is configured, `dev_mode` = whether
    /// the server runs in development mode.
    pub fn into_patch(
        self,
        current: &CoreTenantSettings,
        installation_smtp: bool,
        dev_mode: bool,
    ) -> (TenantPatch, Option<CaptchaChange>) {
        let (settings, captcha) = match self.settings {
            Some(p) => p.merge(current),
            None => (None, None),
        };
        (
            TenantPatch {
                display_name: self.display_name,
                host: self.host,
                settings,
                installation_smtp,
                dev_mode,
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
    /// Where RP-initiated logout may redirect after signing out.
    pub post_logout_redirect_uris: Vec<String>,
    /// OIDC Back-Channel Logout endpoint; `null` = none.
    pub backchannel_logout_uri: Option<String>,
    /// Logout tokens carry `sid`.
    pub backchannel_logout_session_required: bool,
    /// Resource indicators (RFC 8707) the client may request.
    pub allowed_resources: Vec<String>,
    /// Client MFA policy; `null` = the tenant's. The strictest of both wins.
    pub mfa_policy: Option<MfaPolicy>,
    /// Organization policy (`organization` authorization parameter and org claims).
    pub organization: OrgClientPolicy,
    /// The client may only use pushed authorization requests (RFC 9126 §6).
    pub require_pushed_authorization_requests: bool,
    /// `application` or `agent` (an AI agent; never skips consent).
    pub client_kind: ClientKind,
    /// May use the native headless flow API (administrator-registered first-party clients
    /// with PKCE only).
    pub headless_native: bool,
    /// OIDC `client_uri`, the app's home page; `null` = none. The end-user pages link to it
    /// ("Back to <app>") only for administrator-registered (static) clients; values of dynamic
    /// and metadata-document clients are stored and shown here but never rendered to end users.
    pub client_uri: Option<String>,
    /// OIDC `initiate_login_uri`, where the app starts a sign-in (preferred over `client_uri`
    /// for "Back to <app>"); `null` = none. Same rendering rule as `client_uri`.
    pub initiate_login_uri: Option<String>,
    /// How the client came to exist. Dynamic and CIMD clients can be deleted like any client;
    /// a deleted CIMD client is fetched again on its next use if the CIMD policy allows it.
    pub registration_source: ClientSource,
    /// CIMD clients: when the cached metadata document must be fetched again; `null` otherwise.
    #[schema(format = DateTime)]
    pub metadata_expires_at: Option<String>,
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
            post_logout_redirect_uris: c.post_logout_redirect_uris,
            backchannel_logout_uri: c.backchannel_logout_uri,
            backchannel_logout_session_required: c.backchannel_logout_session_required,
            allowed_resources: c.allowed_resources,
            mfa_policy: c.mfa_policy.map(Into::into),
            organization: c.organization.into(),
            require_pushed_authorization_requests: c.require_pushed_authorization_requests,
            client_kind: c.client_kind.into(),
            headless_native: c.headless_native,
            client_uri: c.client_uri,
            initiate_login_uri: c.initiate_login_uri,
            registration_source: c.registration_source.into(),
            metadata_expires_at: c.metadata_expires_at.map(ts),
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
    /// Redirect URI rules of the application type.
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// Absolute, no fragment; https (http only to loopback).
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// Default `false`.
    #[serde(default)]
    pub backchannel_logout_session_required: bool,
    /// Absolute URIs without fragment or query (RFC 8707).
    #[serde(default)]
    pub allowed_resources: Vec<String>,
    /// Default `null` (the tenant's policy).
    #[serde(default)]
    pub mfa_policy: Option<MfaPolicy>,
    /// Default `off`. Must be `off` in the system tenant.
    #[serde(default)]
    pub organization: Option<OrgClientPolicy>,
    /// Default `false`. The client may only use pushed authorization requests (RFC 9126 §6).
    #[serde(default)]
    pub require_pushed_authorization_requests: Option<bool>,
    /// Default `application`. An `agent` must use `consent_mode` `required` (422 otherwise).
    #[serde(default)]
    pub client_kind: Option<ClientKind>,
    /// Default `false`. Needs `consent_mode` `skip_first_party`, PKCE and `client_kind`
    /// `application` (422 otherwise).
    #[serde(default)]
    pub headless_native: Option<bool>,
    /// The app's home page (OIDC `client_uri`): an absolute https URL with a host, no userinfo
    /// and no fragment, at most 2048 characters; http only for localhost and loopback addresses
    /// (422 otherwise). Shown to end users ("Back to <app>") for administrator-registered
    /// clients only.
    #[serde(default)]
    pub client_uri: Option<String>,
    /// Where the app starts a sign-in (OIDC `initiate_login_uri`); the rules of `client_uri`.
    #[serde(default)]
    pub initiate_login_uri: Option<String>,
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
            post_logout_redirect_uris: self.post_logout_redirect_uris.clone(),
            backchannel_logout_uri: self.backchannel_logout_uri.clone(),
            backchannel_logout_session_required: self.backchannel_logout_session_required,
            allowed_resources: self.allowed_resources.clone(),
            mfa_policy: self.mfa_policy.map(Into::into),
            organization: self.organization.map_or(defaults.organization, Into::into),
            require_pushed_authorization_requests: self
                .require_pushed_authorization_requests
                .unwrap_or(defaults.require_pushed_authorization_requests),
            client_kind: self.client_kind.map_or(defaults.client_kind, Into::into),
            headless_native: self.headless_native.unwrap_or(defaults.headless_native),
            client_uri: self.client_uri.clone(),
            initiate_login_uri: self.initiate_login_uri.clone(),
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
    #[serde(default)]
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// `null` removes the back-channel logout URI.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub backchannel_logout_uri: Option<Option<String>>,
    #[serde(default)]
    pub backchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub allowed_resources: Option<Vec<String>>,
    /// `null` falls back to the tenant's policy.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<MfaPolicy>)]
    pub mfa_policy: Option<Option<MfaPolicy>>,
    /// Must stay `off` in the system tenant.
    #[serde(default)]
    pub organization: Option<OrgClientPolicy>,
    #[serde(default)]
    pub require_pushed_authorization_requests: Option<bool>,
    /// An `agent` must use `consent_mode` `required` (422 otherwise).
    #[serde(default)]
    pub client_kind: Option<ClientKind>,
    /// Needs `consent_mode` `skip_first_party`, PKCE, `client_kind` `application` and an
    /// administrator-registered client (422 otherwise).
    #[serde(default)]
    pub headless_native: Option<bool>,
    /// `null` removes the home page; the rules of `CreateClient.client_uri`.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub client_uri: Option<Option<String>>,
    /// `null` removes the initiate-login URI; the rules of `CreateClient.client_uri`.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub initiate_login_uri: Option<Option<String>>,
}

impl UpdateClient {
    /// The registration patch and the options patch.
    pub fn into_parts(self) -> (ClientPatch, ClientOptionsPatch) {
        let options = ClientOptionsPatch {
            token_format: self.token_format.map(Into::into),
            consent_mode: self.consent_mode.map(Into::into),
            id_token_signed_response_alg: self.id_token_signed_response_alg,
            can_introspect: self.can_introspect,
            post_logout_redirect_uris: self.post_logout_redirect_uris,
            backchannel_logout_uri: self.backchannel_logout_uri,
            backchannel_logout_session_required: self.backchannel_logout_session_required,
            allowed_resources: self.allowed_resources,
            mfa_policy: self.mfa_policy.map(|m| m.map(Into::into)),
            organization: self.organization.map(Into::into),
            require_pushed_authorization_requests: self.require_pushed_authorization_requests,
            client_kind: self.client_kind.map(Into::into),
            headless_native: self.headless_native,
            client_uri: self.client_uri,
            initiate_login_uri: self.initiate_login_uri,
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

// ---------------------------------------------------------------------------------------------
// Upstream connections
// ---------------------------------------------------------------------------------------------

/// Endpoint overrides of a social preset (`null` = the preset's value). Absolute https URLs
/// (plain http only to loopback hosts).
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EndpointOverrides {
    pub issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    /// GitHub only: REST API base.
    pub api_base_url: Option<String>,
}

impl From<EndpointOverrides> for CoreEndpointOverrides {
    fn from(o: EndpointOverrides) -> Self {
        Self {
            issuer: o.issuer,
            authorization_endpoint: o.authorization_endpoint,
            token_endpoint: o.token_endpoint,
            userinfo_endpoint: o.userinfo_endpoint,
            jwks_uri: o.jwks_uri,
            api_base_url: o.api_base_url,
        }
    }
}

impl From<CoreEndpointOverrides> for EndpointOverrides {
    fn from(o: CoreEndpointOverrides) -> Self {
        Self {
            issuer: o.issuer,
            authorization_endpoint: o.authorization_endpoint,
            token_endpoint: o.token_endpoint,
            userinfo_endpoint: o.userinfo_endpoint,
            jwks_uri: o.jwks_uri,
            api_base_url: o.api_base_url,
        }
    }
}

/// Sign in with Apple: the team and key the `.p8` private key (the connection secret) belongs
/// to.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AppleConfig {
    pub team_id: String,
    pub key_id: String,
}

/// A social preset (Google, Apple, Microsoft, GitHub).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SocialConnectionConfig {
    pub provider: SocialProvider,
    pub client_id: String,
    /// Requested scopes; empty = the preset's defaults.
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub endpoints: EndpointOverrides,
    /// Microsoft only: `common` (default), `organizations`, `consumers` or a tenant id.
    #[serde(default)]
    pub microsoft_tenant: Option<String>,
    /// Microsoft only: accepted `tid` values (empty = any).
    #[serde(default)]
    pub allowed_tenants: Vec<String>,
    /// Google only: accepted `hd` values (empty = any).
    #[serde(default)]
    pub hosted_domains: Vec<String>,
    /// Apple only (required there).
    #[serde(default)]
    pub apple: Option<AppleConfig>,
}

/// A generic OpenID Connect provider (discovery at `{issuer}/.well-known/openid-configuration`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OidcConnectionConfig {
    /// Absolute https URL (plain http only to loopback hosts).
    pub issuer: String,
    pub client_id: String,
    /// `openid` is always requested.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Default `true`.
    #[serde(default = "default_true")]
    pub use_pkce: bool,
    /// Also call the UserInfo endpoint after the ID token was validated.
    #[serde(default)]
    pub fetch_userinfo: bool,
}

/// JSON pointers (RFC 6901, e.g. `/id`) into a generic OAuth2 profile response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimMapping {
    pub subject: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// A generic OAuth2 provider (no ID token; identity from a profile endpoint).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuth2ConnectionConfig {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub client_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Default `true`.
    #[serde(default = "default_true")]
    pub use_pkce: bool,
    pub mapping: ClaimMapping,
}

fn default_true() -> bool {
    true
}

wire_enum!(
    /// SAML `NameIDFormat` requested from and accepted from the IdP (`transient` is refused:
    /// it cannot identify a returning user).
    NameIdFormat => CoreNameIdFormat { Unspecified, EmailAddress, Persistent, Transient }
);

impl Default for NameIdFormat {
    fn default() -> Self {
        CoreNameIdFormat::default().into()
    }
}

/// Which assertion attributes (matched by `Name` or `FriendlyName`) carry the profile values;
/// absent or `null` = not mapped.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SamlAttributeMapping {
    pub email: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub name: Option<String>,
}

/// A SAML 2.0 identity provider (organization connections only; experimental, needs the
/// operator flag `saml_experimental`). Certificates are public material and shown as PEM.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SamlConnectionConfig {
    /// The IdP's entity ID (1-1024 bytes).
    pub idp_entity_id: String,
    /// The IdP's single sign-on URL for the HTTP-Redirect binding (https).
    pub sso_url: String,
    /// 1-3 IdP signing certificates, one PEM `CERTIFICATE` block each (rollover).
    pub signing_certs: Vec<String>,
    /// Default `unspecified`.
    #[serde(default)]
    pub name_id_format: NameIdFormat,
    #[serde(default)]
    pub attributes: SamlAttributeMapping,
    /// Where the IdP metadata was imported from (https), for the record.
    #[serde(default)]
    pub metadata_url: Option<String>,
}

/// Connection configuration, tagged by `type`. It never contains the client secret.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConnectionConfig {
    Social(SocialConnectionConfig),
    Oidc(OidcConnectionConfig),
    Oauth2(OAuth2ConnectionConfig),
    /// Organization connections only (422 at tenant level).
    Saml(SamlConnectionConfig),
}

impl From<ConnectionConfig> for CoreConnectionConfig {
    fn from(c: ConnectionConfig) -> Self {
        match c {
            ConnectionConfig::Social(s) => Self::Social(CoreSocialConfig {
                provider: s.provider.into(),
                client_id: s.client_id,
                scopes: s.scopes,
                endpoints: s.endpoints.into(),
                microsoft_tenant: s.microsoft_tenant,
                allowed_tenants: s.allowed_tenants,
                hosted_domains: s.hosted_domains,
                apple: s.apple.map(|a| CoreAppleConfig {
                    team_id: a.team_id,
                    key_id: a.key_id,
                }),
            }),
            ConnectionConfig::Oidc(o) => Self::Oidc(CoreOidcConfig {
                issuer: o.issuer,
                client_id: o.client_id,
                scopes: o.scopes,
                use_pkce: o.use_pkce,
                fetch_userinfo: o.fetch_userinfo,
            }),
            ConnectionConfig::Oauth2(o) => Self::Oauth2(CoreOAuth2Config {
                authorization_endpoint: o.authorization_endpoint,
                token_endpoint: o.token_endpoint,
                userinfo_endpoint: o.userinfo_endpoint,
                client_id: o.client_id,
                scopes: o.scopes,
                use_pkce: o.use_pkce,
                mapping: CoreClaimMapping {
                    subject: o.mapping.subject,
                    email: o.mapping.email,
                    email_verified: o.mapping.email_verified,
                    name: o.mapping.name,
                },
            }),
            ConnectionConfig::Saml(c) => Self::Saml(CoreSamlConfig {
                idp_entity_id: c.idp_entity_id,
                sso_url: c.sso_url,
                signing_certs: c.signing_certs,
                name_id_format: c.name_id_format.into(),
                attributes: CoreSamlAttributeMapping {
                    email: c.attributes.email,
                    given_name: c.attributes.given_name,
                    family_name: c.attributes.family_name,
                    name: c.attributes.name,
                },
                metadata_url: c.metadata_url,
            }),
        }
    }
}

impl From<CoreConnectionConfig> for ConnectionConfig {
    fn from(c: CoreConnectionConfig) -> Self {
        match c {
            CoreConnectionConfig::Saml(c) => Self::Saml(SamlConnectionConfig {
                idp_entity_id: c.idp_entity_id,
                sso_url: c.sso_url,
                signing_certs: c.signing_certs,
                name_id_format: c.name_id_format.into(),
                attributes: SamlAttributeMapping {
                    email: c.attributes.email,
                    given_name: c.attributes.given_name,
                    family_name: c.attributes.family_name,
                    name: c.attributes.name,
                },
                metadata_url: c.metadata_url,
            }),
            CoreConnectionConfig::Social(s) => Self::Social(SocialConnectionConfig {
                provider: s.provider.into(),
                client_id: s.client_id,
                scopes: s.scopes,
                endpoints: s.endpoints.into(),
                microsoft_tenant: s.microsoft_tenant,
                allowed_tenants: s.allowed_tenants,
                hosted_domains: s.hosted_domains,
                apple: s.apple.map(|a| AppleConfig {
                    team_id: a.team_id,
                    key_id: a.key_id,
                }),
            }),
            CoreConnectionConfig::Oidc(o) => Self::Oidc(OidcConnectionConfig {
                issuer: o.issuer,
                client_id: o.client_id,
                scopes: o.scopes,
                use_pkce: o.use_pkce,
                fetch_userinfo: o.fetch_userinfo,
            }),
            CoreConnectionConfig::Oauth2(o) => Self::Oauth2(OAuth2ConnectionConfig {
                authorization_endpoint: o.authorization_endpoint,
                token_endpoint: o.token_endpoint,
                userinfo_endpoint: o.userinfo_endpoint,
                client_id: o.client_id,
                scopes: o.scopes,
                use_pkce: o.use_pkce,
                mapping: ClaimMapping {
                    subject: o.mapping.subject,
                    email: o.mapping.email,
                    email_verified: o.mapping.email_verified,
                    name: o.mapping.name,
                },
            }),
        }
    }
}

/// The service-provider values an IdP administrator registers for a SAML connection.
#[derive(Debug, Serialize, ToSchema)]
pub struct SamlSpValues {
    /// SP entity ID (audience): `{issuer}/saml/{slug}`.
    pub entity_id: String,
    /// Assertion consumer service URL (HTTP-POST): `{issuer}/ui/login/saml/{slug}/acs`.
    pub acs_url: String,
    /// SP metadata: `{issuer}/saml/{slug}/metadata`.
    pub metadata_url: String,
}

/// Values read from IdP metadata (`md:EntityDescriptor`) to prefill a SAML connection. Nothing
/// is stored.
#[derive(Debug, Serialize, ToSchema)]
pub struct SamlMetadataView {
    pub idp_entity_id: String,
    pub sso_url: String,
    /// PEM certificates (public material).
    pub signing_certs: Vec<String>,
    /// The URL the metadata was fetched from (absent for pasted XML).
    pub metadata_url: Option<String>,
}

impl SamlMetadataView {
    pub fn new(m: IdpMetadata, metadata_url: Option<String>) -> Self {
        Self {
            idp_entity_id: m.entity_id,
            sso_url: m.sso_url,
            signing_certs: m.signing_certs,
            metadata_url,
        }
    }
}

/// Body of `POST …/organizations/{org}/connections/saml-metadata`: exactly one of `xml` (the
/// pasted metadata document) or `url` (https; fetched through the SSRF-guarded client, at most
/// 1 MiB).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SamlMetadataImport {
    #[serde(default)]
    pub xml: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

/// An upstream connection. The client secret (Apple: the `.p8` key) is write-only:
/// `secret_configured` tells whether one is stored.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionView {
    pub id: Uuid,
    /// Unique per tenant, immutable; part of `redirect_uri`.
    pub slug: String,
    pub display_name: String,
    pub kind: ConnectionKind,
    pub enabled: bool,
    pub config: ConnectionConfig,
    /// Treat the provider's `email_verified` as proof of address ownership (auto-linking).
    pub trust_email_verified: bool,
    pub secret_configured: bool,
    /// The callback URL to register at the provider (SAML: the assertion consumer service).
    pub redirect_uri: String,
    /// The organization the connection belongs to; `null` = a tenant-level connection. An
    /// organization's connection is changed only under that organization.
    pub organization: Option<Uuid>,
    /// SAML only: the service-provider values to register at the IdP.
    pub sp: Option<SamlSpValues>,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub updated_at: String,
}

impl ConnectionView {
    /// The view of `c`; `issuer` is the tenant's issuer (the callback lives below it).
    pub fn new(c: Connection, issuer: &str) -> Self {
        let sp = matches!(c.config, CoreConnectionConfig::Saml(_)).then(|| SamlSpValues {
            entity_id: format!("{issuer}/saml/{}", c.slug),
            acs_url: format!("{issuer}/ui/login/saml/{}/acs", c.slug),
            metadata_url: format!("{issuer}/saml/{}/metadata", c.slug),
        });
        Self {
            id: c.id.0,
            redirect_uri: match &sp {
                Some(sp) => sp.acs_url.clone(),
                None => format!("{issuer}/ui/login/upstream/{}/callback", c.slug),
            },
            sp,
            organization: c.org_id.map(|o| o.0),
            kind: c.kind().into(),
            slug: c.slug,
            display_name: c.display_name,
            enabled: c.enabled,
            config: c.config.into(),
            trust_email_verified: c.trust_email_verified,
            secret_configured: c.secret_enc.is_some(),
            created_at: ts(c.created_at),
            updated_at: ts(c.updated_at),
        }
    }
}

/// Connections in slug order (a tenant's list includes its organizations' connections).
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectionList {
    pub items: Vec<ConnectionView>,
}

/// Body of `POST /tenants/{slug}/connections`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateConnection {
    /// 1-63 characters of a-z, 0-9 and '-', starting with a letter or digit.
    pub slug: String,
    pub display_name: String,
    /// Default `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub config: ConnectionConfig,
    /// Client secret; Apple: the `.p8` private key PEM. Write-only.
    #[serde(default)]
    #[schema(format = Password)]
    pub secret: Option<String>,
    /// Default: `true` for Google, Apple and GitHub, `false` otherwise.
    #[serde(default)]
    pub trust_email_verified: Option<bool>,
    /// Required to trust email addresses asserted by Microsoft, which can be unverified
    /// ("nOAuth"). Default `false`.
    #[serde(default)]
    pub accept_email_trust_risk: bool,
}

impl std::fmt::Debug for CreateConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateConnection")
            .field("slug", &self.slug)
            .field("display_name", &self.display_name)
            .field("enabled", &self.enabled)
            .field("config", &self.config)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field("trust_email_verified", &self.trust_email_verified)
            .field("accept_email_trust_risk", &self.accept_email_trust_risk)
            .finish()
    }
}

impl From<CreateConnection> for NewConnectionInput {
    fn from(c: CreateConnection) -> Self {
        Self {
            slug: c.slug,
            display_name: c.display_name,
            enabled: c.enabled,
            config: c.config.into(),
            secret: c.secret.map(SecretString::from),
            trust_email_verified: c.trust_email_verified,
            accept_email_trust_risk: c.accept_email_trust_risk,
        }
    }
}

/// Body of `PATCH …/connections/{id}`: absent fields stay unchanged. The slug is immutable and
/// `config` must keep the kind; the secret is changed with `PUT …/secret`.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateConnection {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// The complete new configuration (same kind).
    #[serde(default)]
    pub config: Option<ConnectionConfig>,
    #[serde(default)]
    pub trust_email_verified: Option<bool>,
    /// Required when turning on email trust for a Microsoft connection.
    #[serde(default)]
    pub accept_email_trust_risk: bool,
}

impl From<UpdateConnection> for ConnectionPatch {
    fn from(u: UpdateConnection) -> Self {
        Self {
            display_name: u.display_name,
            enabled: u.enabled,
            config: u.config.map(Into::into),
            trust_email_verified: u.trust_email_verified,
            accept_email_trust_risk: u.accept_email_trust_risk,
        }
    }
}

/// Body of `PUT …/connections/{id}/secret`: a new secret, or `null` to remove it. The field is
/// required.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PutConnectionSecret {
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>, format = Password, required = true)]
    pub secret: Option<Option<String>>,
}

impl std::fmt::Debug for PutConnectionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PutConnectionSecret")
            .field(
                "secret",
                &self
                    .secret
                    .as_ref()
                    .map(|s| s.as_ref().map(|_| "<redacted>")),
            )
            .finish()
    }
}

wire_enum!(
    /// Lifecycle state of a signing key: `next` (published in the JWKS, not yet signing),
    /// `active` (signs, one per algorithm) or `retired` (published until `expires_at`).
    KeyState => CoreKeyState { Next, Active, Retired }
);

/// A signing algorithm that a tenant key can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum SigningAlg {
    RS256,
    ES256,
    Ed25519,
}

impl From<SigningAlg> for anvil_jose::keys::Alg {
    fn from(a: SigningAlg) -> Self {
        match a {
            SigningAlg::RS256 => Self::RS256,
            SigningAlg::ES256 => Self::ES256,
            SigningAlg::Ed25519 => Self::Ed25519,
        }
    }
}

/// A signing key of a tenant: identification, lifecycle and timestamps only. The private key
/// (sealed or not) and the JWK are never part of this view; the public keys are served by the
/// tenant's `/jwks`.
#[derive(Debug, Serialize, ToSchema)]
pub struct KeyView {
    /// The JWS `kid`.
    pub kid: String,
    /// The JWS `alg` (`RS256`, `ES256`, `Ed25519`).
    pub alg: String,
    pub state: KeyState,
    #[schema(format = DateTime)]
    pub created_at: String,
    /// When the key started signing (absent while `next`).
    #[schema(format = DateTime)]
    pub activated_at: Option<String>,
    #[schema(format = DateTime)]
    pub retired_at: Option<String>,
    /// When a retired key leaves the JWKS.
    #[schema(format = DateTime)]
    pub expires_at: Option<String>,
}

impl From<CoreSigningKey> for KeyView {
    fn from(k: CoreSigningKey) -> Self {
        Self {
            kid: k.kid,
            alg: k.alg,
            state: k.state.into(),
            created_at: ts(k.created_at),
            activated_at: k.activated_at.map(ts),
            retired_at: k.retired_at.map(ts),
            expires_at: k.expires_at.map(ts),
        }
    }
}

/// Every signing key of a tenant, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct KeyList {
    pub items: Vec<KeyView>,
}

/// Body of `POST /tenants/{slug}/keys/rotate`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RotateKeyRequest {
    /// The algorithm to rotate; it must be enabled for the tenant.
    pub alg: SigningAlg,
    /// `false` (default): publish a next key now; the scheduled job activates it after the
    /// prepublish period. `true` (key compromise): activate a new key at once and drop the old
    /// one from the JWKS, so tokens it signed stop verifying.
    #[serde(default)]
    pub immediate: bool,
}

/// Result of a rotation: the kid of the key that signs next.
#[derive(Debug, Serialize, ToSchema)]
pub struct RotateKeyResponse {
    pub kid: String,
}
