//! SAML XML handling (`ports::SamlXml`, ORG-03): one strict parser, profile pre-check, XML-DSig
//! verification against the configured certificates, extraction from the verified node only.
//!
//! Owned by plan 06-09 (uppsala + bergshamra-dsig on aws-lc, attack corpus). Until then the
//! adapter exists so services can be wired, and every method refuses with
//! [`SamlXmlReject::Unavailable`]: nothing is parsed, verified or encoded.

use std::sync::Arc;

use anvil_core::model::{IdpMetadata, SamlAssertionData};
use anvil_core::ports::{SamlXml, SamlXmlReject};

use crate::state::AppState;

/// The production [`SamlXml`] (module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct SamlXmlAdapter;

impl SamlXml for SamlXmlAdapter {
    fn verify_response(
        &self,
        _xml: &[u8],
        _signing_certs: &[String],
    ) -> Result<SamlAssertionData, SamlXmlReject> {
        // TRANSITIONAL(06-09): no SAML response is accepted before the verifier exists.
        Err(SamlXmlReject::Unavailable)
    }

    fn parse_metadata(&self, _xml: &[u8]) -> Result<IdpMetadata, SamlXmlReject> {
        // TRANSITIONAL(06-09)
        Err(SamlXmlReject::Unavailable)
    }

    fn encode_redirect(&self, _authn_request_xml: &str) -> Result<String, SamlXmlReject> {
        // TRANSITIONAL(06-09)
        Err(SamlXmlReject::Unavailable)
    }
}

impl AppState {
    /// The SAML XML adapter services use (stateless).
    pub(crate) fn saml_xml(&self) -> Arc<dyn SamlXml> {
        Arc::new(SamlXmlAdapter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_refuses_until_the_verifier_exists() {
        let a = SamlXmlAdapter;
        assert_eq!(
            a.verify_response(b"<x/>", &[]).err(),
            Some(SamlXmlReject::Unavailable)
        );
        assert_eq!(
            a.parse_metadata(b"<x/>").err(),
            Some(SamlXmlReject::Unavailable)
        );
        assert_eq!(
            a.encode_redirect("<x/>").err(),
            Some(SamlXmlReject::Unavailable)
        );
    }
}
