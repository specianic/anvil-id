//! Declarative tenant configuration parsing and validation (ADM-07, SEC-07).
//!
//! The input is fed as JSON into `TenantConfigDocument` (the admin API body; the CLI converts
//! YAML into the same document) and, when it parses, through `validate_document` with the
//! production redirect URI rules and permissive stand-ins for the I/O-backed checks.
//! Invariants checked on every input:
//! - parsing and validation never panic;
//! - a serialized document never carries a secret value (inline secrets serialize as
//!   `{configured: true}`);
//! - for a valid document, normalisation is idempotent and a document planned against its own
//!   normalised form is empty (re-applying is a no-op).
#![no_main]

use anvil_core::error::CoreError;
use anvil_core::model::{ApplicationType, SecretInput, TenantConfigDocument};
use anvil_core::oauth::redirect::validate_redirect_uri;
use anvil_core::ports::{AttributeSchemaCheck, EmailTemplateCheck, SchemaIssue, TemplateIssue};
use anvil_core::service::config::{Validators, normalize_document, plan, validate_document};
use anvil_core::service::webhook::{UrlRefusal, WebhookUrlCheck};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

struct ObjectSchemas;
impl AttributeSchemaCheck for ObjectSchemas {
    fn check_definition(&self, schema: &Value) -> Result<(), SchemaIssue> {
        if schema.is_object() {
            Ok(())
        } else {
            Err(SchemaIssue {
                message: "not an object".into(),
            })
        }
    }
    fn validate(&self, _: &Value, _: &Value) -> Result<(), Vec<String>> {
        Ok(())
    }
}

struct HttpsOnly;
impl WebhookUrlCheck for HttpsOnly {
    fn check(&self, url: &url::Url) -> Result<(), UrlRefusal> {
        if url.scheme() == "https" && url.host_str().is_some() {
            Ok(())
        } else {
            Err(UrlRefusal::Invalid)
        }
    }
}

struct AnyTemplate;
impl EmailTemplateCheck for AnyTemplate {
    fn check(
        &self,
        _: anvil_core::model::EmailKind,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<(), TemplateIssue> {
        Ok(())
    }
}

fn redirect(uri: &str, app: ApplicationType) -> Result<(), CoreError> {
    validate_redirect_uri(uri, app)
}

fn secrets(doc: &TenantConfigDocument) -> Vec<&SecretInput> {
    let mut out: Vec<&SecretInput> = Vec::new();
    out.extend(doc.clients.iter().filter_map(|c| c.secret.as_ref()));
    out.extend(doc.connections.iter().filter_map(|c| c.secret.as_ref()));
    out.extend(doc.webhooks.iter().filter_map(|w| w.secret.as_ref()));
    out.extend(doc.smtp.iter().filter_map(|s| s.password.as_ref()));
    out
}

fuzz_target!(|data: &[u8]| {
    let Ok(doc) = serde_json::from_slice::<TenantConfigDocument>(data) else {
        return;
    };
    let serialized = serde_json::to_value(&doc).expect("a parsed document serializes");
    for s in secrets(&doc) {
        if let SecretInput::Inline { .. } = s {
            assert!(
                !serialized.to_string().contains("\"value\":"),
                "an inline secret was serialized"
            );
        }
    }
    let v = Validators {
        redirect,
        attribute_check: &ObjectSchemas,
        url_check: &HttpsOnly,
        template_check: &AnyTemplate,
    };
    if validate_document(&doc, &v).is_ok() {
        let normalized = normalize_document(&doc);
        assert_eq!(
            normalize_document(&normalized),
            normalized,
            "not idempotent"
        );
        let p = plan(&normalized, &normalized, &|_, _| true);
        assert!(p.is_empty(), "self plan not empty: {p:?}");
    }
});
