//! Theming tokens per tenant and per client (UI-03): colours, fonts, radius, logo and custom CSS,
//! rendered as CSS variables. Drafts back the console's live preview.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::ids::{OrgId, SecretHash, TenantId};

/// Which pages a branding record applies to. Precedence: client > org > tenant (the most
/// specific record that exists wins).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BrandingScope {
    Tenant,
    Client(String),
    /// Pages shown while a user signs in to an organization.
    Org(OrgId),
}

impl BrandingScope {
    /// The stored key: `""` for the tenant, `client:{client_id}` for a client, `org:{uuid}` for
    /// an organization.
    pub fn scope_key(&self) -> String {
        match self {
            Self::Tenant => String::new(),
            Self::Client(id) => format!("client:{id}"),
            Self::Org(id) => format!("org:{id}"),
        }
    }

    /// Inverse of [`Self::scope_key`]; `None` for an unknown key.
    pub fn from_key(key: &str) -> Option<Self> {
        if key.is_empty() {
            return Some(Self::Tenant);
        }
        if let Some(id) = key.strip_prefix("org:") {
            return uuid::Uuid::parse_str(id)
                .ok()
                .filter(|u| u.hyphenated().to_string() == id)
                .map(|u| Self::Org(OrgId(u)));
        }
        key.strip_prefix("client:")
            .filter(|id| !id.is_empty())
            .map(|id| Self::Client(id.to_owned()))
    }
}

/// Theme colours (CSS colour strings, validated by the branding policy). `None` = theme default.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ThemeColors {
    pub primary: Option<String>,
    pub primary_text: Option<String>,
    pub bg: Option<String>,
    pub surface: Option<String>,
    pub text: Option<String>,
    pub muted: Option<String>,
    pub border: Option<String>,
    pub focus: Option<String>,
    pub danger: Option<String>,
}

/// Design tokens of a branding record (stored as JSON).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ThemeTokens {
    pub colors: ThemeColors,
    /// Colours for `prefers-color-scheme: dark`; `None` = derived from the theme default.
    pub colors_dark: Option<ThemeColors>,
    pub font_family: Option<String>,
    pub radius_px: Option<u8>,
}

/// A logo image, stored by content hash.
#[derive(Clone, PartialEq, Eq)]
pub struct Logo {
    pub content_type: String,
    /// Lowercase hex SHA-256 of `bytes`.
    pub sha256: String,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for Logo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Logo")
            .field("content_type", &self.content_type)
            .field("sha256", &self.sha256)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// A stored branding record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branding {
    pub tenant_id: TenantId,
    pub scope_key: String,
    pub tokens: ThemeTokens,
    /// Sanitised custom CSS (served same-origin under the strict CSP).
    pub custom_css: Option<String>,
    pub logo_sha256: Option<String>,
    pub logo_type: Option<String>,
    pub updated_at: OffsetDateTime,
}

/// What a branding update does to the logo.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LogoChange {
    #[default]
    Keep,
    Clear,
    Set(Logo),
}

/// Replaces tokens and custom CSS of a scope; the logo per [`LogoChange`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandingUpdate {
    pub tokens: ThemeTokens,
    pub custom_css: Option<String>,
    pub logo: LogoChange,
}

/// An unpublished branding draft for the console's live preview, reachable with a preview token
/// (stored only as its hash) until `preview_expires_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandingDraft {
    pub tokens: ThemeTokens,
    pub custom_css: Option<String>,
    pub preview_token_hash: SecretHash,
    pub preview_expires_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_keys_round_trip() {
        assert_eq!(BrandingScope::Tenant.scope_key(), "");
        assert_eq!(
            BrandingScope::Client("app".into()).scope_key(),
            "client:app"
        );
        for s in [BrandingScope::Tenant, BrandingScope::Client("a:b".into())] {
            assert_eq!(BrandingScope::from_key(&s.scope_key()), Some(s));
        }
        assert_eq!(BrandingScope::from_key("client:"), None);
        assert_eq!(BrandingScope::from_key("org:x"), None);
        assert_eq!(BrandingScope::from_key("org:"), None);
        let org = OrgId::new_v7();
        let scope = BrandingScope::Org(org);
        assert_eq!(scope.scope_key(), format!("org:{org}"));
        assert_eq!(BrandingScope::from_key(&scope.scope_key()), Some(scope));
        assert_eq!(
            BrandingScope::from_key(&format!("org:{}", org.0.simple())),
            None,
            "only the canonical hyphenated form is a key"
        );
        assert_eq!(BrandingScope::from_key("other:x"), None);
    }

    #[test]
    fn tokens_parse_from_partial_json() {
        let t: ThemeTokens = serde_json::from_str(r##"{"colors":{"primary":"#123456"}}"##).unwrap();
        assert_eq!(t.colors.primary.as_deref(), Some("#123456"));
        assert_eq!(t.radius_px, None);
        assert_eq!(
            serde_json::from_str::<ThemeTokens>("{}").unwrap(),
            ThemeTokens::default()
        );
    }
}
