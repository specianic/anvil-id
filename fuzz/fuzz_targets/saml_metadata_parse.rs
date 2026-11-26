//! IdP metadata import (ORG-03).
//!
//! Input: arbitrary bytes as an `md:EntityDescriptor` / `md:EntitiesDescriptor` document.
//!
//! Invariants (besides never panicking): an accepted document yields a non-blank entity id, an
//! https SSO URL with a host, and at least one PEM certificate block per signing certificate.
#![no_main]

use anvil_core::ports::SamlXml;
use anvil_web::adapters::saml_xml::SamlXmlAdapter;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(md) = SamlXmlAdapter.parse_metadata(data) else {
        return;
    };
    assert!(!md.entity_id.trim().is_empty());
    let url = url::Url::parse(&md.sso_url).expect("sso url parses");
    assert_eq!(url.scheme(), "https");
    assert!(url.host_str().is_some_and(|h| !h.is_empty()));
    assert!(!md.signing_certs.is_empty());
    for pem in &md.signing_certs {
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        assert_eq!(pem.matches("-----BEGIN").count(), 1);
    }
});
