//! SP-initiated `AuthnRequest`, RelayState and SP metadata (ORG-03).
//!
//! Every document is written from a fixed template; each input value goes through
//! [`super::xml_escape`]. The `AuthnRequest` is unsigned (1.0 profile) and travels over the
//! HTTP-Redirect binding (DEFLATE, base64 and URL encoding happen in the web adapter); the
//! Response is requested over HTTP-POST.

use anvil_jose::encoding::{b64url, b64url_decode};
use uuid::Uuid;

use super::{BINDING_HTTP_POST, NS_ASSERTION, NS_METADATA, NS_PROTOCOL, saml_instant, xml_escape};
use crate::model::{FlowId, NameIdFormat};
use time::OffsetDateTime;

/// RelayState limit of the SAML bindings (§3.4.3, §3.5.3).
pub const MAX_RELAY_STATE_LEN: usize = 80;

/// A request ID from 16 caller-provided random bytes: `_` and 32 lowercase hex characters (an
/// `xs:ID` must not start with a digit).
pub fn request_id(bytes: [u8; 16]) -> String {
    let mut out = String::with_capacity(33);
    out.push('_');
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The values of one `AuthnRequest`.
#[derive(Debug, Clone, Copy)]
pub struct AuthnRequestParams<'a> {
    /// Our entity ID (`Issuer`).
    pub sp_entity_id: &'a str,
    /// Our assertion consumer service URL.
    pub acs_url: &'a str,
    /// The IdP's SSO endpoint.
    pub destination: &'a str,
    /// From [`request_id`]; the Response must answer it in `InResponseTo`.
    pub request_id: &'a str,
    pub issue_instant: OffsetDateTime,
    pub name_id_format: NameIdFormat,
    /// `prompt=login`: ask the IdP to re-authenticate the user.
    pub force_authn: bool,
}

/// The `AuthnRequest` XML.
pub fn authn_request(p: &AuthnRequestParams<'_>) -> String {
    let force = if p.force_authn {
        r#" ForceAuthn="true""#
    } else {
        ""
    };
    format!(
        concat!(
            r#"<samlp:AuthnRequest xmlns:samlp="{ns_p}" xmlns:saml="{ns_a}""#,
            r#" ID="{id}" Version="2.0" IssueInstant="{instant}" Destination="{dest}""#,
            r#" AssertionConsumerServiceURL="{acs}" ProtocolBinding="{binding}"{force}>"#,
            r#"<saml:Issuer>{issuer}</saml:Issuer>"#,
            r#"<samlp:NameIDPolicy Format="{format}" AllowCreate="true"/>"#,
            r#"</samlp:AuthnRequest>"#
        ),
        ns_p = NS_PROTOCOL,
        ns_a = NS_ASSERTION,
        id = xml_escape(p.request_id),
        instant = saml_instant(p.issue_instant),
        dest = xml_escape(p.destination),
        acs = xml_escape(p.acs_url),
        binding = BINDING_HTTP_POST,
        force = force,
        issuer = xml_escape(p.sp_entity_id),
        format = p.name_id_format.urn(),
    )
}

/// RelayState: `{flow_id}.{base64url(16 random bytes)}`, 59 bytes.
pub fn relay_state(flow: FlowId, nonce: [u8; 16]) -> String {
    format!("{flow}.{}", b64url(&nonce))
}

/// Inverse of [`relay_state`]. `None` unless the value is exactly that canonical form (at most
/// 80 bytes, a lowercase hyphenated UUID, a dot, 22 base64url characters of 16 bytes).
pub fn split_relay_state(value: &str) -> Option<(FlowId, [u8; 16])> {
    if value.len() > MAX_RELAY_STATE_LEN {
        return None;
    }
    let (flow, nonce) = value.split_once('.')?;
    let uuid = Uuid::parse_str(flow).ok()?;
    if uuid.hyphenated().to_string() != flow {
        return None;
    }
    let bytes: [u8; 16] = b64url_decode(nonce).ok()?.try_into().ok()?;
    Some((FlowId(uuid), bytes))
}

/// The SP metadata: one `SPSSODescriptor` for SAML 2.0, unsigned requests, signed assertions
/// wanted, one HTTP-POST assertion consumer service, no `KeyDescriptor` (no encryption, no
/// request signing).
pub fn sp_metadata(entity_id: &str, acs_url: &str, name_id_format: NameIdFormat) -> String {
    format!(
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<md:EntityDescriptor xmlns:md="{ns_md}" entityID="{entity}">"#,
            r#"<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true""#,
            r#" protocolSupportEnumeration="{ns_p}">"#,
            r#"<md:NameIDFormat>{format}</md:NameIDFormat>"#,
            r#"<md:AssertionConsumerService Binding="{binding}" Location="{acs}" index="0""#,
            r#" isDefault="true"/>"#,
            r#"</md:SPSSODescriptor>"#,
            r#"</md:EntityDescriptor>"#
        ),
        ns_md = NS_METADATA,
        entity = xml_escape(entity_id),
        ns_p = NS_PROTOCOL,
        format = name_id_format.urn(),
        binding = BINDING_HTTP_POST,
        acs = xml_escape(acs_url),
    )
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    const SP: &str = "https://id.example.test/t/acme/saml/okta";
    const ACS: &str = "https://id.example.test/t/acme/ui/login/saml/okta/acs";
    const IDP_SSO: &str = "https://idp.example.test/sso";

    fn params(force_authn: bool) -> AuthnRequestParams<'static> {
        AuthnRequestParams {
            sp_entity_id: SP,
            acs_url: ACS,
            destination: IDP_SSO,
            request_id: "_00112233445566778899aabbccddeeff",
            issue_instant: datetime!(2026-11-26 09:30:00 UTC),
            name_id_format: NameIdFormat::EmailAddress,
            force_authn,
        }
    }

    #[test]
    fn request_ids_are_underscore_and_32_hex() {
        let id = request_id([0xAB; 16]);
        assert_eq!(id, format!("_{}", "ab".repeat(16)));
        let id = request_id(*b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f");
        assert_eq!(id, "_000102030405060708090a0b0c0d0e0f");
        assert_eq!(id.len(), 33);
    }

    #[test]
    fn authn_request_carries_exactly_the_values() {
        let xml = authn_request(&params(false));
        assert_eq!(
            xml,
            concat!(
                r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol""#,
                r#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion""#,
                r#" ID="_00112233445566778899aabbccddeeff" Version="2.0""#,
                r#" IssueInstant="2026-11-26T09:30:00Z" Destination="https://idp.example.test/sso""#,
                r#" AssertionConsumerServiceURL="https://id.example.test/t/acme/ui/login/saml/okta/acs""#,
                r#" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">"#,
                r#"<saml:Issuer>https://id.example.test/t/acme/saml/okta</saml:Issuer>"#,
                r#"<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress""#,
                r#" AllowCreate="true"/>"#,
                r#"</samlp:AuthnRequest>"#
            )
        );
        assert!(!xml.contains("ForceAuthn"));
    }

    #[test]
    fn prompt_login_sets_force_authn() {
        let xml = authn_request(&params(true));
        assert!(xml.contains(r#" ForceAuthn="true">"#), "{xml}");
    }

    #[test]
    fn authn_request_escapes_every_input() {
        let evil = r#"x"<&'>y"#;
        let p = AuthnRequestParams {
            sp_entity_id: evil,
            acs_url: evil,
            destination: evil,
            request_id: evil,
            ..params(false)
        };
        let xml = authn_request(&p);
        assert!(!xml.contains(evil));
        assert_eq!(
            xml.matches("x&quot;&lt;&amp;&apos;&gt;y").count(),
            4,
            "{xml}"
        );
        // The only raw quotes are the template's own attribute delimiters.
        assert!(!xml.contains("x\""));
    }

    #[test]
    fn relay_state_round_trips_within_80_bytes() {
        let flow = FlowId::new_v7();
        let rs = relay_state(flow, [7; 16]);
        assert_eq!(rs.len(), 59);
        assert!(rs.len() <= MAX_RELAY_STATE_LEN);
        assert_eq!(split_relay_state(&rs), Some((flow, [7; 16])));
    }

    #[test]
    fn malformed_relay_state_is_refused() {
        let flow = FlowId::new_v7();
        let good = relay_state(flow, [1; 16]);
        let nonce = b64url(&[1; 16]);
        let cases = [
            String::new(),
            flow.to_string(),
            format!("{flow}."),
            format!(".{nonce}"),
            format!("{}.{nonce}", flow.to_string().to_uppercase()),
            format!("{}.{nonce}", flow.0.simple()),
            format!("{flow}.{}", b64url(&[1; 15])),
            format!("{flow}.{}", b64url(&[1; 17])),
            format!("{flow}.{nonce}="),
            format!("{flow}.{nonce}.x"),
            format!("not-a-uuid.{nonce}"),
            format!("{good}{}", "a".repeat(30)),
        ];
        for c in cases {
            assert_eq!(split_relay_state(&c), None, "{c:?}");
        }
    }

    #[test]
    fn sp_metadata_shape() {
        let md = sp_metadata(SP, ACS, NameIdFormat::Persistent);
        assert!(md.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
        assert!(md.contains(&format!(r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{SP}">"#)));
        assert!(
            md.contains(r#"protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol""#)
        );
        assert!(md.contains(r#"AuthnRequestsSigned="false""#));
        assert!(md.contains(r#"WantAssertionsSigned="true""#));
        assert_eq!(md.matches("<md:AssertionConsumerService ").count(), 1);
        assert!(md.contains(&format!(
            r#"<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{ACS}""#
        )));
        assert!(md.contains(
            "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>"
        ));
        assert!(!md.contains("KeyDescriptor"));
        assert_eq!(md.matches("<md:SPSSODescriptor ").count(), 1);
    }

    #[test]
    fn sp_metadata_escapes_inputs() {
        let md = sp_metadata("e\"<x>", "a&b", NameIdFormat::Unspecified);
        assert!(md.contains(r#"entityID="e&quot;&lt;x&gt;""#));
        assert!(md.contains(r#"Location="a&amp;b""#));
    }
}
