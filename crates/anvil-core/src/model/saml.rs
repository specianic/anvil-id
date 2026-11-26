//! SAML 2.0 service-provider connection model (ORG-03, decision D4).
//!
//! AnvilID is a narrow SP: SP-initiated Web Browser SSO, signed assertions required, no
//! IdP-initiated responses, no encrypted assertions. This module holds pure data: the
//! connection configuration, the values extracted from a *verified* assertion, and the identity
//! core validation produces. XML parsing and signature verification live in the web adapter.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::ids::str_enum;
use crate::error::CoreError;

/// Longest IdP entity ID, in bytes.
pub const MAX_SAML_ENTITY_ID_LEN: usize = 1024;

/// Most IdP signing certificates per connection (rollover).
pub const MAX_SAML_SIGNING_CERTS: usize = 3;

/// Largest PEM certificate, in bytes.
pub const MAX_SAML_CERT_PEM_LEN: usize = 16 * 1024;

/// SAML `NameIDFormat` requested from and accepted from the IdP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameIdFormat {
    #[default]
    Unspecified,
    EmailAddress,
    Persistent,
    Transient,
}

str_enum!(NameIdFormat {
    Unspecified => "unspecified",
    EmailAddress => "email_address",
    Persistent => "persistent",
    Transient => "transient",
});

impl NameIdFormat {
    /// The SAML URN of this format.
    pub fn urn(self) -> &'static str {
        match self {
            Self::Unspecified => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            Self::EmailAddress => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            Self::Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            Self::Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        }
    }

    /// Inverse of [`Self::urn`]; `None` for an unknown URN.
    pub fn from_urn(urn: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|f| f.urn() == urn)
    }
}

/// Which assertion attributes (matched by `Name` or `FriendlyName`) carry the profile values.
/// `None` = not mapped.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SamlAttributeMapping {
    pub email: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub name: Option<String>,
}

/// A SAML IdP connection (`ConnectionConfig::Saml`). Certificates are public material; only
/// their public keys are used (chain and validity are ignored for pinned keys).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamlConfig {
    pub idp_entity_id: String,
    /// The IdP's SSO endpoint for the HTTP-Redirect AuthnRequest (https).
    pub sso_url: String,
    /// 1-3 PEM certificates (one `CERTIFICATE` block each).
    pub signing_certs: Vec<String>,
    #[serde(default)]
    pub name_id_format: NameIdFormat,
    #[serde(default)]
    pub attributes: SamlAttributeMapping,
    /// Where the IdP metadata was imported from (refetched through the SSRF-guarded client).
    #[serde(default)]
    pub metadata_url: Option<String>,
}

fn invalid(field: &'static str, message: &str) -> CoreError {
    CoreError::Validation {
        field,
        message: message.to_owned(),
    }
}

/// Whether `pem` is exactly one PEM `CERTIFICATE` block with a non-empty base64 body.
fn is_single_certificate_pem(pem: &str) -> bool {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let pem = pem.trim();
    let Some(rest) = pem.strip_prefix(BEGIN) else {
        return false;
    };
    let Some(body) = rest.strip_suffix(END) else {
        return false;
    };
    if body.contains("-----") {
        return false;
    }
    let mut chars = 0usize;
    for c in body.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if !(c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')) {
            return false;
        }
        chars += 1;
    }
    chars > 0
}

impl SamlConfig {
    /// Structural checks. Signature-relevant parsing of the certificates happens in the web
    /// adapter; this only refuses shapes that can never work.
    pub fn validate(&self) -> Result<(), CoreError> {
        let entity = self.idp_entity_id.trim();
        if entity.is_empty() || self.idp_entity_id.len() > MAX_SAML_ENTITY_ID_LEN {
            return Err(invalid(
                "idp_entity_id",
                "must be 1-1024 bytes and not blank",
            ));
        }
        if !self.sso_url.starts_with("https://") || self.sso_url.len() <= "https://".len() {
            return Err(invalid("sso_url", "must be an https URL"));
        }
        if self.signing_certs.is_empty() || self.signing_certs.len() > MAX_SAML_SIGNING_CERTS {
            return Err(invalid(
                "signing_certs",
                "between 1 and 3 signing certificates are required",
            ));
        }
        for cert in &self.signing_certs {
            if cert.len() > MAX_SAML_CERT_PEM_LEN || !is_single_certificate_pem(cert) {
                return Err(invalid(
                    "signing_certs",
                    "each entry must be one PEM CERTIFICATE block of at most 16 KiB",
                ));
            }
        }
        if self.name_id_format == NameIdFormat::Transient {
            return Err(invalid(
                "name_id_format",
                "a transient NameID cannot identify a returning user",
            ));
        }
        if let Some(url) = &self.metadata_url
            && !url.starts_with("https://")
        {
            return Err(invalid("metadata_url", "must be an https URL"));
        }
        Ok(())
    }
}

/// The values read from imported IdP metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpMetadata {
    pub entity_id: String,
    pub sso_url: String,
    pub signing_certs: Vec<String>,
}

/// `SubjectConfirmation` (bearer) values of a verified assertion.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SamlSubjectConfirmation {
    pub method: String,
    pub recipient: Option<String>,
    pub not_on_or_after: Option<OffsetDateTime>,
    pub in_response_to: Option<String>,
}

/// Values extracted by the web adapter from the signature-verified assertion node (and its
/// enclosing Response). Core validation decides on these values only; the XML never reaches
/// core.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SamlAssertionData {
    pub response_destination: Option<String>,
    pub response_in_response_to: Option<String>,
    pub status_code: String,
    pub response_issuer: Option<String>,
    pub issue_instant: Option<OffsetDateTime>,
    pub assertion_id: String,
    pub issuer: String,
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub subject_confirmation: Option<SamlSubjectConfirmation>,
    pub not_before: Option<OffsetDateTime>,
    pub not_on_or_after: Option<OffsetDateTime>,
    /// One entry per `AudienceRestriction`; every restriction must contain the SP entity ID.
    pub audiences: Vec<Vec<String>>,
    pub has_authn_statement: bool,
    pub session_index: Option<String>,
    pub attributes: BTreeMap<String, Vec<String>>,
}

/// The identity core validation produces from a verified assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlIdentity {
    /// The NameID (stable subject at the IdP).
    pub subject: String,
    pub email: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str =
        "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ==\n-----END CERTIFICATE-----\n";

    fn config() -> SamlConfig {
        SamlConfig {
            idp_entity_id: "https://idp.example.test/entity".into(),
            sso_url: "https://idp.example.test/sso".into(),
            signing_certs: vec![CERT.into()],
            name_id_format: NameIdFormat::Unspecified,
            attributes: SamlAttributeMapping::default(),
            metadata_url: None,
        }
    }

    #[test]
    fn name_id_formats_round_trip() {
        for f in NameIdFormat::ALL {
            assert_eq!(NameIdFormat::parse(f.as_str()), Some(*f));
            assert_eq!(NameIdFormat::from_urn(f.urn()), Some(*f));
        }
        assert_eq!(NameIdFormat::from_urn("urn:x"), None);
    }

    #[test]
    fn valid_config_passes_and_json_has_defaults() {
        config().validate().unwrap();
        let json = r#"{"idp_entity_id":"e","sso_url":"https://i/sso","signing_certs":[]}"#;
        let c: SamlConfig = serde_json::from_str(json).unwrap();
        assert_eq!(c.name_id_format, NameIdFormat::Unspecified);
        assert_eq!(c.attributes, SamlAttributeMapping::default());
        assert_eq!(c.metadata_url, None);
    }

    #[test]
    fn validate_rejects_bad_configs() {
        type Mutation = Box<dyn Fn(&mut SamlConfig)>;
        let cases: Vec<(&str, Mutation)> = vec![
            ("idp_entity_id", Box::new(|c| c.idp_entity_id = "  ".into())),
            (
                "idp_entity_id",
                Box::new(|c| c.idp_entity_id = "e".repeat(1025)),
            ),
            (
                "sso_url",
                Box::new(|c| c.sso_url = "http://idp.example.test/sso".into()),
            ),
            ("sso_url", Box::new(|c| c.sso_url = "https://".into())),
            ("signing_certs", Box::new(|c| c.signing_certs.clear())),
            (
                "signing_certs",
                Box::new(|c| c.signing_certs = vec![CERT.into(); 4]),
            ),
            (
                "signing_certs",
                Box::new(|c| c.signing_certs = vec!["not a pem".into()]),
            ),
            (
                "signing_certs",
                Box::new(|c| c.signing_certs = vec![format!("{CERT}{CERT}")]),
            ),
            (
                "signing_certs",
                Box::new(|c| {
                    c.signing_certs =
                        vec!["-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----".into()]
                }),
            ),
            (
                "signing_certs",
                Box::new(|c| {
                    c.signing_certs = vec![format!(
                        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                        "A".repeat(17 * 1024)
                    )]
                }),
            ),
            (
                "name_id_format",
                Box::new(|c| c.name_id_format = NameIdFormat::Transient),
            ),
            (
                "metadata_url",
                Box::new(|c| c.metadata_url = Some("http://idp.example.test/md".into())),
            ),
        ];
        for (field, mutate) in cases {
            let mut c = config();
            mutate(&mut c);
            match c.validate() {
                Err(CoreError::Validation { field: f, .. }) => assert_eq!(f, field),
                other => panic!("expected a validation error on {field}, got {other:?}"),
            }
        }
    }
}
