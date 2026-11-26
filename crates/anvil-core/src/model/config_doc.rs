//! The declarative tenant configuration document (`kind: TenantConfig`, `version: 1`, ADM-07).
//!
//! Objects are keyed by natural keys (tenant slug, `client_id`, connection slug, role name,
//! attribute name, template kind, webhook name), never by database ids, so a document exported
//! from one instance applies to another. Secrets never appear in clear in an export:
//! [`SecretInput`] serializes as `{configured: true|false}`; an inline value is accepted on input
//! only. The JSON form here is the admin API wire form; the CLI converts it to and from YAML.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::attribute::AttributeDefinition;
use super::branding::ThemeTokens;
use super::client::{
    ApplicationType, ClientAuthMethod, ClientType, ConsentMode, GrantType, TokenFormat,
};
use super::connection::ConnectionConfig;
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
    /// Tenant-wide branding and per-client overrides (logos are not part of version 1).
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
}

fn default_true() -> bool {
    true
}

/// An upstream identity-provider connection, keyed by slug.
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
}

/// A role, keyed by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSection {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub permissions: Vec<String>,
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
