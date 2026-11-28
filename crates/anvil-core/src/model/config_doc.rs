//! The declarative tenant configuration document (`kind: TenantConfig`, `version: 1`, ADM-07).
//!
//! Objects are keyed by natural keys (tenant slug, `client_id`, connection slug, role name,
//! attribute name, template kind, webhook name), never by database ids, so a document exported
//! from one instance applies to another. Secrets never appear in clear in an export:
//! [`SecretInput`] serializes as `{configured: true|false}`; an inline value is accepted on input
//! only. The JSON form here is the admin API wire form; the CLI converts it to and from YAML.
//!
//! Optional keys added within version 1 (rc.4; docs/COMPATIBILITY.md) keep today's meaning when
//! they are absent, also under prune: an absent branding `logo` leaves the stored logo, and an
//! absent `organizations` key touches no organization.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize};

use super::attribute::AttributeDefinition;
use super::branding::ThemeTokens;
use super::client::{
    ApplicationType, ClientAuthMethod, ClientKind, ClientType, ConsentMode, GrantType, TokenFormat,
};
use super::connection::ConnectionConfig;
use super::organization::OrgClientPolicy;
use super::tenant::{MfaPolicy, TenantSettings};
use super::webhook::WebhookEventType;
use crate::error::CoreError;

/// The only document version this release reads and writes.
pub const TENANT_CONFIG_VERSION: u32 = 1;

/// The document kind marker. Any other value fails to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ConfigKind {
    #[default]
    TenantConfig,
}

/// One tenant's full configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfigDocument {
    /// Must equal [`TENANT_CONFIG_VERSION`] ([`TenantConfigDocument::check_header`]).
    pub version: u32,
    pub kind: ConfigKind,
    pub tenant: TenantSection,
    /// Static clients only (dynamic and CIMD clients are runtime state), keyed by `client_id`.
    #[serde(default)]
    pub clients: Vec<ClientSection>,
    /// Keyed by slug.
    #[serde(default)]
    pub connections: Vec<ConnectionSection>,
    /// Tenant-wide branding and per-client overrides, each with an optional logo.
    #[serde(default)]
    pub branding: Vec<BrandingSection>,
    /// Keyed by name.
    #[serde(default)]
    pub roles: Vec<RoleSection>,
    /// Keyed by name.
    #[serde(default)]
    pub attributes: Vec<AttributeDefinition>,
    /// Customized templates only, keyed by kind.
    #[serde(default)]
    pub email_templates: Vec<EmailTemplateSection>,
    #[serde(default)]
    pub smtp: Option<SmtpSection>,
    /// Keyed by name.
    #[serde(default)]
    pub webhooks: Vec<WebhookSection>,
    /// Organizations, keyed by slug, with what they own (roles, connections, domain claims,
    /// branding). `None` (key absent) = organizations are not managed by this document: nothing
    /// of them is planned, changed or pruned. Organizations themselves are never deleted by a
    /// document; runtime data (members, invitations, identity links, org role assignments) and
    /// domain verification are never part of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organizations: Option<Vec<OrganizationSection>>,
}

impl TenantConfigDocument {
    /// Rejects documents of another version.
    pub fn check_header(&self) -> Result<(), CoreError> {
        if self.version != TENANT_CONFIG_VERSION {
            return Err(CoreError::Validation {
                field: "version",
                message: format!(
                    "unsupported document version {}, expected {TENANT_CONFIG_VERSION}",
                    self.version
                ),
            });
        }
        Ok(())
    }
}

/// The tenant itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantSection {
    pub slug: String,
    pub display_name: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub settings: TenantSettings,
}

/// A static client, keyed by `client_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSection {
    pub client_id: String,
    pub name: String,
    pub client_type: ClientType,
    pub application_type: ApplicationType,
    pub auth_method: ClientAuthMethod,
    /// The client secret (confidential clients with a secret-based method).
    #[serde(default)]
    pub secret: Option<SecretInput>,
    #[serde(default)]
    pub jwks: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<GrantType>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_true")]
    pub require_pkce: bool,
    #[serde(default)]
    pub token_format: TokenFormat,
    #[serde(default)]
    pub consent_mode: ConsentMode,
    #[serde(default)]
    pub id_token_signed_response_alg: Option<String>,
    #[serde(default)]
    pub can_introspect: bool,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub backchannel_logout_session_required: bool,
    #[serde(default)]
    pub allowed_resources: Vec<String>,
    #[serde(default)]
    pub mfa_policy: Option<MfaPolicy>,
    /// Organization policy; omitted when `off`.
    #[serde(default, skip_serializing_if = "OrgClientPolicy::is_off")]
    pub organization: OrgClientPolicy,
    /// RFC 9126 §6: the client must use pushed authorization requests; omitted when `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_pushed_authorization_requests: bool,
    /// `application` or `agent` (AGT-03; an agent never skips consent); omitted when
    /// `application`.
    #[serde(default, skip_serializing_if = "is_application")]
    pub client_kind: ClientKind,
    /// May use the native headless flow API (first-party, PKCE, not an agent); omitted when
    /// `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub headless_native: bool,
    /// The client's home page (shown to administrators; to end users only for static
    /// clients); omitted when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    /// Where a sign-in started at AnvilID continues at the client (OIDC third-party initiated
    /// login); omitted when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<String>,
}

fn default_true() -> bool {
    true
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if passes a reference"
)]
fn is_false(b: &bool) -> bool {
    !*b
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde skip_serializing_if passes a reference"
)]
fn is_application(k: &ClientKind) -> bool {
    *k == ClientKind::Application
}

/// An upstream identity-provider connection, keyed by slug. At the top level: tenant connections
/// (an organization's connections never appear there). Under `organizations[].connections`: that
/// organization's connections (OIDC, or SAML while `saml_experimental` is on). Both share the
/// tenant's slug namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSection {
    pub slug: String,
    pub display_name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub config: ConnectionConfig,
    /// The upstream client secret (or Apple private key).
    #[serde(default)]
    pub secret: Option<SecretInput>,
    #[serde(default)]
    pub trust_email_verified: bool,
}

/// Branding for the tenant (`client_id: None`) or one client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrandingSection {
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub tokens: ThemeTokens,
    #[serde(default)]
    pub custom_css: Option<String>,
    /// The logo: absent keeps the stored logo, `null` clears it, a value sets it.
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub logo: Option<Option<LogoInput>>,
}

/// Deserializes a present key (including `null`) as `Some`, so that an absent key (`None` by
/// `#[serde(default)]`) and `null` (`Some(None)`) differ.
fn double_option<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// A logo in a branding section.
///
/// - `{data: <base64>}` (input only): the image, checked like an upload (PNG, JPEG or WebP, at
///   most 256 KiB, SVG refused).
/// - `{sha256, content_type}`: a logo already stored in the tenant, by content hash (what an
///   export writes). Unknown in the target tenant = a validation error.
///
/// `{file: path}` is a CLI reference (resolved into `{data}` by `anvilid tenant`); the server
/// refuses it.
#[derive(Clone, PartialEq, Eq)]
pub enum LogoInput {
    Data {
        data: String,
    },
    Stored {
        sha256: String,
        content_type: String,
    },
}

impl std::fmt::Debug for LogoInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data { data } => f
                .debug_struct("Data")
                .field("data", &format_args!("<{} base64 characters>", data.len()))
                .finish(),
            Self::Stored {
                sha256,
                content_type,
            } => f
                .debug_struct("Stored")
                .field("sha256", sha256)
                .field("content_type", content_type)
                .finish(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogoInputWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    /// Accepted by the parser only to refuse it with a clear message.
    #[serde(default, skip_serializing)]
    file: Option<serde_json::Value>,
}

impl Serialize for LogoInput {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = match self {
            Self::Data { data } => LogoInputWire {
                data: Some(data.clone()),
                sha256: None,
                content_type: None,
                file: None,
            },
            Self::Stored {
                sha256,
                content_type,
            } => LogoInputWire {
                data: None,
                sha256: Some(sha256.clone()),
                content_type: Some(content_type.clone()),
                file: None,
            },
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LogoInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = LogoInputWire::deserialize(deserializer)?;
        if wire.file.is_some() {
            return Err(serde::de::Error::custom(
                "logo {file: path} is resolved by the anvilid CLI; send {data: <base64>} or \
                 {sha256, content_type}",
            ));
        }
        match (wire.data, wire.sha256, wire.content_type) {
            (Some(data), None, None) => Ok(Self::Data { data }),
            (None, Some(sha256), Some(content_type)) => Ok(Self::Stored {
                sha256,
                content_type,
            }),
            _ => Err(serde::de::Error::custom(
                "a logo is null, {data: <base64>} or {sha256, content_type}",
            )),
        }
    }
}

/// A role, keyed by name: a tenant role at the top level, an organization-owned role under
/// `organizations[].roles`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSection {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// An organization, keyed by slug, with what it owns. Never carries memberships, invitations,
/// identity links, org role assignments or domain verification state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationSection {
    pub slug: String,
    pub display_name: String,
    /// The organization's MFA requirement; `null` = none.
    #[serde(default)]
    pub mfa_policy: Option<MfaPolicy>,
    /// Free-form JSON object for the integrator.
    #[serde(default = "empty_object")]
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub settings: OrgSettingsSection,
    /// Organization-owned roles, keyed by name.
    #[serde(default)]
    pub roles: Vec<RoleSection>,
    /// The organization's connections, keyed by slug.
    #[serde(default)]
    pub connections: Vec<ConnectionSection>,
    /// Domain claims, keyed by domain.
    #[serde(default)]
    pub domains: Vec<OrgDomainSection>,
    /// The organization's branding (`null` or absent: none; a stored one is removed only with
    /// prune).
    #[serde(default)]
    pub branding: Option<OrgBrandingSection>,
}

fn empty_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Organization settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgSettingsSection {
    /// Roles given to members created by just-in-time provisioning, by name: an organization
    /// role of this entry, otherwise a tenant role.
    #[serde(default)]
    pub default_roles: Vec<String>,
}

/// A domain claim of an organization. A document never marks a domain verified: a new claim is
/// pending with a fresh DNS token, and `routing` / `allow_local_password` take effect only once
/// the domain was verified through DNS (apply the document again after verification).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgDomainSection {
    pub domain: String,
    /// Slug of the routing target, a connection of this organization.
    #[serde(default)]
    pub connection: Option<String>,
    #[serde(default)]
    pub routing: bool,
    #[serde(default = "default_true")]
    pub allow_local_password: bool,
}

/// An organization's branding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgBrandingSection {
    #[serde(default)]
    pub tokens: ThemeTokens,
    #[serde(default)]
    pub custom_css: Option<String>,
    /// Absent keeps the stored logo, `null` clears it, a value sets it.
    #[serde(
        default,
        deserialize_with = "double_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub logo: Option<Option<LogoInput>>,
}

/// A customized email template, keyed by kind (an `EmailKind` storage name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailTemplateSection {
    pub kind: String,
    pub subject: String,
    pub body_html: String,
    pub body_text: String,
}

/// Tenant SMTP settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpSection {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<SecretInput>,
    pub from: String,
    /// An `SmtpTls` storage name (`starttls`, `implicit`, `none`).
    pub tls: String,
}

/// A webhook endpoint, keyed by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookSection {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub events: Vec<WebhookEventType>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// The signing secret. Omitted on create = generated by the server.
    #[serde(default)]
    pub secret: Option<SecretInput>,
}

/// A secret field of the document.
///
/// - Input: `{configured: true}` keeps the current value (`false` clears it), `{value: "..."}`
///   sets it.
/// - Output: always `{configured: <bool>}`. An inline value serializes as `{configured: true}`,
///   so a secret never round-trips out in clear.
#[derive(Clone)]
pub enum SecretInput {
    Configured { configured: bool },
    Inline { value: SecretString },
}

impl SecretInput {
    /// Whether a secret is (or will be) set.
    pub fn is_configured(&self) -> bool {
        match self {
            Self::Configured { configured } => *configured,
            Self::Inline { .. } => true,
        }
    }
}

impl std::fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configured { configured } => f
                .debug_struct("Configured")
                .field("configured", configured)
                .finish(),
            Self::Inline { .. } => f
                .debug_struct("Inline")
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}

/// Document equality (plan computation and tests). Not constant-time: never use it to check a
/// presented credential.
impl PartialEq for SecretInput {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Configured { configured: a }, Self::Configured { configured: b }) => a == b,
            (Self::Inline { value: a }, Self::Inline { value: b }) => {
                a.expose_secret() == b.expose_secret()
            }
            _ => false,
        }
    }
}

impl Eq for SecretInput {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretInputWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    configured: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

impl Serialize for SecretInput {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SecretInputWire {
            configured: Some(self.is_configured()),
            value: None,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretInput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SecretInputWire::deserialize(deserializer)?;
        match (wire.configured, wire.value) {
            (Some(configured), None) => Ok(Self::Configured { configured }),
            (None, Some(value)) if !value.is_empty() => Ok(Self::Inline {
                value: SecretString::from(value),
            }),
            (None, Some(_)) => Err(serde::de::Error::custom("secret value must not be empty")),
            _ => Err(serde::de::Error::custom(
                "a secret is either {configured: bool} or {value: string}",
            )),
        }
    }
}

/// Kind of a configuration object in a [`ConfigPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigObjectKind {
    Tenant,
    Client,
    Connection,
    Branding,
    Role,
    Attribute,
    EmailTemplate,
    Smtp,
    Webhook,
    /// Key: org slug.
    Organization,
    /// Key: `{org slug}/{role name}`.
    OrgRole,
    /// Key: `{org slug}/{connection slug}`.
    OrgConnection,
    /// Key: `{org slug}/{domain}`.
    OrgDomain,
    /// Key: org slug.
    OrgBranding,
}

/// One changed field. Secret fields carry no values (`before` and `after` are `None`); only the
/// fact that they change is reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDiff {
    pub field: String,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
}

/// One object to create, update or delete, by natural key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigChange {
    pub kind: ConfigObjectKind,
    pub key: String,
    /// Field diffs for updates; empty for creates and deletes.
    #[serde(default)]
    pub fields: Vec<FieldDiff>,
}

/// The plan computed before applying a document. Applying an unchanged document yields an empty
/// plan (idempotency). Deletions are only planned when pruning is requested.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConfigPlan {
    pub creates: Vec<ConfigChange>,
    pub updates: Vec<ConfigChange>,
    pub deletes: Vec<ConfigChange>,
}

impl ConfigPlan {
    /// Nothing to do.
    pub fn is_empty(&self) -> bool {
        self.creates.is_empty() && self.updates.is_empty() && self.deletes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> &'static str {
        r#"{"version":1,"kind":"TenantConfig","tenant":{"slug":"acme","display_name":"Acme"}}"#
    }

    #[test]
    fn minimal_document_parses_with_defaults() {
        let d: TenantConfigDocument = serde_json::from_str(minimal()).unwrap();
        d.check_header().unwrap();
        assert_eq!(d.tenant.settings, TenantSettings::default());
        assert!(d.clients.is_empty() && d.webhooks.is_empty() && d.smtp.is_none());
    }

    #[test]
    fn unknown_fields_kind_and_version_are_rejected() {
        let extra = minimal().replace("\"version\":1", "\"version\":1,\"bogus\":true");
        assert!(serde_json::from_str::<TenantConfigDocument>(&extra).is_err());
        let kind = minimal().replace("TenantConfig", "Other");
        assert!(serde_json::from_str::<TenantConfigDocument>(&kind).is_err());
        let v2 = minimal().replace("\"version\":1", "\"version\":2");
        let d: TenantConfigDocument = serde_json::from_str(&v2).unwrap();
        assert!(d.check_header().is_err());
        let nested = minimal().replace(
            "\"display_name\":\"Acme\"",
            "\"display_name\":\"A\",\"x\":1",
        );
        assert!(serde_json::from_str::<TenantConfigDocument>(&nested).is_err());
    }

    #[test]
    fn secret_input_never_serializes_a_value() {
        let inline: SecretInput = serde_json::from_str(r#"{"value":"hunter2"}"#).unwrap();
        assert!(inline.is_configured());
        let out = serde_json::to_string(&inline).unwrap();
        assert_eq!(out, r#"{"configured":true}"#);
        assert!(!format!("{inline:?}").contains("hunter2"));
        let kept: SecretInput = serde_json::from_str(r#"{"configured":false}"#).unwrap();
        assert_eq!(kept, SecretInput::Configured { configured: false });
        assert_eq!(
            serde_json::to_string(&kept).unwrap(),
            r#"{"configured":false}"#
        );
    }

    #[test]
    fn secret_input_rejects_ambiguous_or_empty_input() {
        for bad in [
            r#"{}"#,
            r#"{"value":""}"#,
            r#"{"configured":true,"value":"x"}"#,
            r#"{"secret":"x"}"#,
            r#""plain""#,
        ] {
            assert!(serde_json::from_str::<SecretInput>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn client_v10_fields_default_and_are_omitted_when_default() {
        let base = r#"{"client_id":"web","name":"Web","client_type":"public","application_type":"web","auth_method":"none"}"#;
        let c: ClientSection = serde_json::from_str(base).unwrap();
        assert!(!c.require_pushed_authorization_requests && !c.headless_native);
        assert_eq!(c.client_kind, ClientKind::Application);
        let out = serde_json::to_value(&c).unwrap();
        for key in [
            "require_pushed_authorization_requests",
            "client_kind",
            "headless_native",
        ] {
            assert!(out.get(key).is_none(), "{key}");
        }
        let set = base.replace(
            "\"auth_method\":\"none\"",
            "\"auth_method\":\"none\",\"require_pushed_authorization_requests\":true,\"client_kind\":\"agent\",\"headless_native\":true",
        );
        let c: ClientSection = serde_json::from_str(&set).unwrap();
        assert!(c.require_pushed_authorization_requests && c.headless_native);
        assert_eq!(c.client_kind, ClientKind::Agent);
        let out = serde_json::to_value(&c).unwrap();
        assert_eq!(out["client_kind"], "agent");
        assert_eq!(out["require_pushed_authorization_requests"], true);
        assert_eq!(out["headless_native"], true);
        let unknown = base.replace(
            "\"auth_method\":\"none\"",
            "\"auth_method\":\"none\",\"client_kind\":\"robot\"",
        );
        assert!(serde_json::from_str::<ClientSection>(&unknown).is_err());
    }

    // Compatibility policy (docs/COMPATIBILITY.md): version 1 is the only document version
    // in 1.x; another version or a missing one is refused, never guessed.
    #[test]
    fn config_doc_version_1_accepted() {
        let d: TenantConfigDocument = serde_json::from_str(minimal()).unwrap();
        assert_eq!(d.version, TENANT_CONFIG_VERSION);
        assert_eq!(TENANT_CONFIG_VERSION, 1);
        d.check_header().unwrap();
    }

    #[test]
    fn config_doc_unknown_version_refused() {
        for v in ["0", "2", "99"] {
            let doc = minimal().replace("\"version\":1", &format!("\"version\":{v}"));
            let d: TenantConfigDocument = serde_json::from_str(&doc).unwrap();
            match d.check_header() {
                Err(CoreError::Validation { field, message }) => {
                    assert_eq!(field, "version");
                    assert!(
                        message.contains(&format!("unsupported document version {v}")),
                        "{message}"
                    );
                }
                other => panic!("version {v} accepted: {other:?}"),
            }
        }
        let missing = minimal().replace("\"version\":1,", "");
        let err = serde_json::from_str::<TenantConfigDocument>(&missing).unwrap_err();
        assert!(err.to_string().contains("missing field `version`"), "{err}");
        let negative = minimal().replace("\"version\":1", "\"version\":-1");
        assert!(serde_json::from_str::<TenantConfigDocument>(&negative).is_err());
    }

    #[test]
    fn config_doc_rc3_document_parses_unchanged() {
        let d: TenantConfigDocument = serde_json::from_str(minimal()).unwrap();
        assert!(d.organizations.is_none());
        // Nothing new is written for a document without the new keys.
        let out = serde_json::to_value(&d).unwrap();
        assert!(out.get("organizations").is_none());
        let b: BrandingSection = serde_json::from_str(r#"{"tokens":{}}"#).unwrap();
        assert_eq!(b.logo, None);
        assert!(serde_json::to_value(&b).unwrap().get("logo").is_none());
        let base = r#"{"client_id":"web","name":"Web","client_type":"public","application_type":"web","auth_method":"none"}"#;
        let c: ClientSection = serde_json::from_str(base).unwrap();
        assert!(c.client_uri.is_none() && c.initiate_login_uri.is_none());
        let out = serde_json::to_value(&c).unwrap();
        assert!(out.get("client_uri").is_none() && out.get("initiate_login_uri").is_none());
    }

    #[test]
    fn config_doc_logo_variants() {
        let b: BrandingSection = serde_json::from_str(r#"{"logo":null}"#).unwrap();
        assert_eq!(b.logo, Some(None));
        assert_eq!(serde_json::to_string(&b.logo).unwrap(), "null");
        let b: BrandingSection = serde_json::from_str(r#"{"logo":{"data":"iVBO"}}"#).unwrap();
        assert_eq!(
            b.logo,
            Some(Some(LogoInput::Data {
                data: "iVBO".into()
            }))
        );
        assert!(!format!("{b:?}").contains("iVBO"));
        let sha = "a".repeat(64);
        let b: BrandingSection = serde_json::from_str(&format!(
            r#"{{"logo":{{"sha256":"{sha}","content_type":"image/png"}}}}"#
        ))
        .unwrap();
        assert_eq!(
            serde_json::to_value(&b).unwrap()["logo"],
            serde_json::json!({"sha256": sha, "content_type": "image/png"})
        );
        for bad in [
            r#"{"logo":{"file":"logo.png"}}"#,
            r#"{"logo":{}}"#,
            r#"{"logo":{"data":"x","sha256":"y","content_type":"image/png"}}"#,
            r#"{"logo":{"sha256":"y"}}"#,
            r#"{"logo":{"url":"https://x"}}"#,
            r#"{"logo":"plain"}"#,
        ] {
            assert!(
                serde_json::from_str::<BrandingSection>(bad).is_err(),
                "{bad}"
            );
        }
        let err = serde_json::from_str::<BrandingSection>(r#"{"logo":{"file":"l.png"}}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("anvilid CLI"), "{err}");
    }

    #[test]
    fn config_doc_organizations_parse_and_refuse_unknown_keys() {
        let org = r#"{"slug":"acme","display_name":"Acme","domains":[{"domain":"acme.example"}]}"#;
        let full = format!(
            r#"{{"version":1,"kind":"TenantConfig","tenant":{{"slug":"t1","display_name":"T"}},"organizations":[{org}]}}"#
        );
        let d: TenantConfigDocument = serde_json::from_str(&full).unwrap();
        let o = &d.organizations.as_ref().unwrap()[0];
        assert_eq!(o.metadata, serde_json::json!({}));
        assert!(o.domains[0].allow_local_password && !o.domains[0].routing);
        assert!(o.branding.is_none() && o.roles.is_empty());
        // Verification state, runtime data and unknown keys are refused at every level.
        for (from, to) in [
            (
                r#""domain":"acme.example""#,
                r#""domain":"acme.example","verified":true"#,
            ),
            (
                r#""domain":"acme.example""#,
                r#""domain":"acme.example","status":"verified""#,
            ),
            (
                r#""domain":"acme.example""#,
                r#""domain":"acme.example","token":"x""#,
            ),
            (
                r#""domain":"acme.example""#,
                r#""domain":"acme.example","verified_at":"2026-01-01T00:00:00Z""#,
            ),
            (
                r#""display_name":"Acme""#,
                r#""display_name":"Acme","members":[]"#,
            ),
            (
                r#""display_name":"Acme""#,
                r#""display_name":"Acme","invitations":[]"#,
            ),
            (
                r#""display_name":"Acme""#,
                r#""display_name":"Acme","settings":{"default_role_ids":[]}"#,
            ),
        ] {
            let bad = full.replace(from, to);
            assert_ne!(bad, full);
            assert!(
                serde_json::from_str::<TenantConfigDocument>(&bad).is_err(),
                "{to}"
            );
        }
    }

    #[test]
    fn plan_is_empty() {
        let mut p = ConfigPlan::default();
        assert!(p.is_empty());
        p.updates.push(ConfigChange {
            kind: ConfigObjectKind::Role,
            key: "admin".into(),
            fields: vec![],
        });
        assert!(!p.is_empty());
    }
}
