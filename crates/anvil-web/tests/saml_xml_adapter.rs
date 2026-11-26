//! `SamlXmlAdapter` (ORG-03): a response signed by the test IdP verifies against the configured
//! certificate and yields every field from the verified assertion; extraction feeds core's
//! `saml::validate::check`; parse caps (DTD, size, depth); IdP metadata import; the HTTP-Redirect
//! encoding. The attack corpus is `security_saml.rs`.
//!
//! Every key and certificate is generated at test time (saml_support).

mod saml_support;

use std::io::Read as _;

use anvil_core::model::{SamlAttributeMapping, SamlIdentity};
use anvil_core::ports::{SamlXml, SamlXmlReject};
use anvil_core::saml::validate::{self, SamlExpected, SamlReject};
use anvil_jose::encoding::b64std_decode;
use anvil_web::adapters::saml_xml::{MAX_RESPONSE_BYTES, SamlXmlAdapter};
use saml_support::*;
use time::{Duration, OffsetDateTime};

fn verify(
    xml: &str,
    certs: &[String],
) -> Result<anvil_core::model::SamlAssertionData, SamlXmlReject> {
    SamlXmlAdapter.verify_response(xml.as_bytes(), certs)
}

fn expected() -> SamlExpected {
    SamlExpected {
        sp_entity_id: SP_ENTITY_ID.into(),
        acs_url: ACS_URL.into(),
        request_id: REQUEST_ID.into(),
        idp_entity_id: IDP_ENTITY_ID.into(),
        attributes: SamlAttributeMapping {
            email: Some("mail".into()),
            given_name: Some("givenName".into()),
            family_name: None,
            name: None,
        },
        skew: validate::DEFAULT_SKEW,
    }
}

/// Second precision, as the builder writes instants.
fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc().replace_nanosecond(0).unwrap()
}

#[test]
fn signed_response_verifies_and_yields_every_field() {
    let key = IdpKey::rsa();
    let now = now();
    let opts = ResponseOpts::valid(now);
    let xml = signed_response(&key, &opts);
    let data = verify(&xml, &[key.cert_pem()]).expect("valid response");

    assert_eq!(data.response_destination.as_deref(), Some(ACS_URL));
    assert_eq!(data.response_in_response_to.as_deref(), Some(REQUEST_ID));
    assert_eq!(data.status_code, STATUS_SUCCESS);
    assert_eq!(data.response_issuer.as_deref(), Some(IDP_ENTITY_ID));
    assert_eq!(data.issue_instant, Some(now));
    assert_eq!(data.assertion_id, ASSERTION_ID);
    assert_eq!(data.issuer, IDP_ENTITY_ID);
    assert_eq!(data.name_id, NAME_ID);
    assert_eq!(data.name_id_format.as_deref(), Some(FORMAT_EMAIL));
    let sc = data.subject_confirmation.as_ref().expect("confirmation");
    assert_eq!(sc.method, CM_BEARER);
    assert_eq!(sc.recipient.as_deref(), Some(ACS_URL));
    assert_eq!(sc.in_response_to.as_deref(), Some(REQUEST_ID));
    assert_eq!(sc.not_on_or_after, Some(now + Duration::minutes(5)));
    assert!(data.has_conditions);
    assert_eq!(data.not_before, Some(now - Duration::seconds(30)));
    assert_eq!(data.not_on_or_after, Some(now + Duration::minutes(5)));
    assert_eq!(data.audiences, vec![vec![SP_ENTITY_ID.to_owned()]]);
    assert!(data.has_authn_statement);
    assert_eq!(data.session_index.as_deref(), Some("_session1"));
    // Attributes are keyed by Name and, when different, by FriendlyName.
    assert_eq!(
        data.attributes.get("urn:oid:0.9.2342.19200300.100.1.3"),
        Some(&vec![NAME_ID.to_owned()])
    );
    assert_eq!(data.attributes.get("mail"), Some(&vec![NAME_ID.to_owned()]));
    assert_eq!(
        data.attributes.get("givenName"),
        Some(&vec!["Alice".to_owned()])
    );
    assert_eq!(data.attributes.len(), 3);

    // The extracted values pass core's rules end to end.
    let identity = validate::check(&data, &expected(), now).expect("core accepts");
    assert_eq!(
        identity,
        SamlIdentity {
            subject: NAME_ID.into(),
            email: Some(NAME_ID.into()),
            given_name: Some("Alice".into()),
            family_name: None,
            name: None,
        }
    );
}

#[test]
fn ecdsa_and_response_plus_assertion_signatures_verify() {
    for (key, sign_response) in [
        (IdpKey::ecdsa(), false),
        (IdpKey::ecdsa(), true),
        (IdpKey::rsa(), true),
    ] {
        let opts = ResponseOpts {
            sign_response,
            ..ResponseOpts::valid(now())
        };
        let xml = signed_response(&key, &opts);
        assert_eq!(
            xml.matches("<ds:Signature ").count(),
            1 + usize::from(sign_response)
        );
        let data = verify(&xml, &[key.cert_pem()]).expect("valid");
        assert_eq!(data.name_id, NAME_ID);
    }
}

#[test]
fn one_of_several_configured_certificates_verifies() {
    let old = IdpKey::rsa();
    let new = IdpKey::rsa();
    let xml = signed_response(&new, &ResponseOpts::default());
    verify(&xml, &[old.cert_pem(), new.cert_pem()]).expect("rollover");
}

#[test]
fn another_certificate_or_none_is_refused() {
    let key = IdpKey::rsa();
    let other = IdpKey::rsa();
    let xml = signed_response(&key, &ResponseOpts::default());
    assert_eq!(
        verify(&xml, &[other.cert_pem()]),
        Err(SamlXmlReject::UntrustedKey)
    );
    assert_eq!(verify(&xml, &[]), Err(SamlXmlReject::UntrustedKey));
    // A key of another type (EC certificate configured, RSA signature).
    assert_eq!(
        verify(&xml, &[IdpKey::ecdsa().cert_pem()]),
        Err(SamlXmlReject::UntrustedKey)
    );
    // A configured value that is not a certificate.
    assert_eq!(
        verify(&xml, &["not a certificate".to_owned()]),
        Err(SamlXmlReject::UntrustedKey)
    );
}

#[test]
fn doctype_anywhere_is_dtd() {
    let key = IdpKey::rsa();
    let xml = signed_response(&key, &ResponseOpts::default());
    let cert = [key.cert_pem()];
    let in_prolog = format!("<!DOCTYPE samlp:Response>{xml}");
    assert_eq!(verify(&in_prolog, &cert), Err(SamlXmlReject::Dtd));
    let after_decl = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE r [ ]>\n{xml}");
    assert_eq!(verify(&after_decl, &cert), Err(SamlXmlReject::Dtd));
    let inside = insert_after(&xml, "<samlp:Status>", "<!DOCTYPE x>");
    assert_eq!(verify(&inside, &cert), Err(SamlXmlReject::Dtd));
}

#[test]
fn oversized_input_is_size() {
    let key = IdpKey::rsa();
    let xml = signed_response(&key, &ResponseOpts::default());
    let padded = format!("{xml}{}", " ".repeat(MAX_RESPONSE_BYTES + 1 - xml.len()));
    assert_eq!(padded.len(), MAX_RESPONSE_BYTES + 1);
    assert_eq!(verify(&padded, &[key.cert_pem()]), Err(SamlXmlReject::Size));
    // Exactly at the cap is parsed (and verifies: trailing whitespace is allowed after the root).
    let at_cap = &padded[..MAX_RESPONSE_BYTES];
    verify(at_cap, &[key.cert_pem()]).expect("at the cap");
}

#[test]
fn depth_65_is_parse_and_depth_64_parses() {
    let nest = |depth: usize| {
        // The Response is level 1, Extensions level 2.
        let inner = depth - 2;
        format!(
            "<samlp:Response xmlns:samlp=\"{NS_PROTOCOL}\" Version=\"2.0\"><samlp:Extensions>{}{}</samlp:Extensions></samlp:Response>",
            "<x>".repeat(inner),
            "</x>".repeat(inner)
        )
    };
    let cert = [IdpKey::ecdsa().cert_pem()];
    assert_eq!(verify(&nest(65), &cert), Err(SamlXmlReject::Parse));
    // 64 levels parse; the document is then refused for its structure, not by the parser.
    assert_eq!(verify(&nest(64), &cert), Err(SamlXmlReject::Structure));
}

#[test]
fn not_utf8_or_not_xml_is_parse() {
    let cert = [IdpKey::ecdsa().cert_pem()];
    assert_eq!(
        SamlXmlAdapter.verify_response(b"<a>\xff</a>", &cert),
        Err(SamlXmlReject::Parse)
    );
    assert_eq!(verify("<a><b></a>", &cert), Err(SamlXmlReject::Parse));
    assert_eq!(verify("", &cert), Err(SamlXmlReject::Parse));
    let latin1 = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>";
    assert_eq!(verify(latin1, &cert), Err(SamlXmlReject::Parse));
}

/// Deferred item from 06-05: `has_conditions` tells a missing Conditions element apart from a
/// Conditions element without NotOnOrAfter, so core reports two different reasons.
#[test]
fn has_conditions_is_false_without_conditions() {
    let key = IdpKey::rsa();
    let now = now();
    let opts = ResponseOpts {
        conditions: None,
        ..ResponseOpts::valid(now)
    };
    let data = verify(&signed_response(&key, &opts), &[key.cert_pem()]).expect("verifies");
    assert!(!data.has_conditions);
    assert_eq!(data.not_on_or_after, None);
    assert!(data.audiences.is_empty());
    assert_eq!(
        validate::check(&data, &expected(), now),
        Err(SamlReject::MissingConditions)
    );
}

#[test]
fn has_conditions_is_true_for_conditions_without_not_on_or_after() {
    let key = IdpKey::rsa();
    let now = now();
    let opts = ResponseOpts {
        conditions: Some(Conditions {
            not_before: Some(now - Duration::seconds(30)),
            not_on_or_after: None,
            audiences: vec![vec![SP_ENTITY_ID.into()]],
        }),
        ..ResponseOpts::valid(now)
    };
    let data = verify(&signed_response(&key, &opts), &[key.cert_pem()]).expect("verifies");
    assert!(data.has_conditions);
    assert_eq!(data.not_on_or_after, None);
    assert_eq!(
        validate::check(&data, &expected(), now),
        Err(SamlReject::ConditionsMissingNotOnOrAfter)
    );
}

#[test]
fn several_audience_restrictions_are_kept_apart() {
    let key = IdpKey::rsa();
    let opts = ResponseOpts {
        conditions: Some(Conditions {
            not_before: None,
            not_on_or_after: Some(now() + Duration::minutes(5)),
            audiences: vec![
                vec![SP_ENTITY_ID.into(), "https://other.example.test".into()],
                vec![],
            ],
        }),
        ..ResponseOpts::default()
    };
    let data = verify(&signed_response(&key, &opts), &[key.cert_pem()]).expect("verifies");
    assert_eq!(
        data.audiences,
        vec![
            vec![
                SP_ENTITY_ID.to_owned(),
                "https://other.example.test".to_owned()
            ],
            vec![]
        ]
    );
}

#[test]
fn malformed_instant_in_the_signed_assertion_is_structure() {
    // The builder writes valid instants; a signed assertion with a bad one is built by hand.
    let key = IdpKey::rsa();
    let opts = ResponseOpts::default();
    let template = assertion_xml(&opts, Some(key.alg));
    let conditions_open = element(&template, "<saml:Conditions", ">").to_owned();
    let template = replace_once(
        &template,
        &conditions_open,
        "<saml:Conditions NotOnOrAfter=\"tomorrow\">",
    );
    let assertion = sign_first(&key, &template);
    let xml = response_xml(&opts, None, &assertion);
    assert_eq!(
        verify(&xml, &[key.cert_pem()]),
        Err(SamlXmlReject::Structure)
    );
}

// ---------------------------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------------------------

fn metadata(sso_location: &str, key_descriptors: &str) -> String {
    format!(
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" \
xmlns:ds=\"{NS_DSIG}\" entityID=\"{IDP_ENTITY_ID}\">\
<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\
{key_descriptors}\
<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp.example.test/post\"/>\
<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"{sso_location}\"/>\
</md:IDPSSODescriptor></md:EntityDescriptor>"
    )
}

fn key_descriptor(usage: Option<&str>, cert_b64: &str) -> String {
    let use_attr = usage.map(|u| format!(" use=\"{u}\"")).unwrap_or_default();
    // Line-wrapped as IdPs publish it.
    let wrapped: Vec<&str> = cert_b64
        .as_bytes()
        .chunks(76)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "<md:KeyDescriptor{use_attr}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>\n{}\n</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>",
        wrapped.join("\n")
    )
}

#[test]
fn metadata_yields_entity_id_https_redirect_sso_and_pem_certs() {
    let signing = IdpKey::rsa();
    let unspecified = IdpKey::ecdsa();
    let encryption = IdpKey::rsa();
    let xml = metadata(
        "https://idp.example.test/sso/redirect",
        &[
            key_descriptor(Some("signing"), &signing.cert_b64()),
            key_descriptor(None, &unspecified.cert_b64()),
            key_descriptor(Some("encryption"), &encryption.cert_b64()),
            // The same signing certificate twice is listed once.
            key_descriptor(Some("signing"), &signing.cert_b64()),
        ]
        .concat(),
    );
    let md = SamlXmlAdapter
        .parse_metadata(xml.as_bytes())
        .expect("metadata");
    assert_eq!(md.entity_id, IDP_ENTITY_ID);
    assert_eq!(md.sso_url, "https://idp.example.test/sso/redirect");
    assert_eq!(
        md.signing_certs,
        vec![signing.cert_pem(), unspecified.cert_pem()]
    );
    // The PEM output is accepted by the response verifier (same certificate format).
    let xml = signed_response(&signing, &ResponseOpts::default());
    verify(&xml, &md.signing_certs).expect("imported certificate verifies");
}

#[test]
fn metadata_in_an_entities_descriptor_with_one_idp() {
    let key = IdpKey::rsa();
    let entity = metadata(
        "https://idp.example.test/sso",
        &key_descriptor(Some("signing"), &key.cert_b64()),
    );
    let sp_only = "<md:EntityDescriptor entityID=\"https://sp.example.test\"><md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"/></md:EntityDescriptor>";
    let wrap = |inner: &str| {
        format!(
            "<md:EntitiesDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">{inner}</md:EntitiesDescriptor>"
        )
    };
    let md = SamlXmlAdapter
        .parse_metadata(wrap(&format!("{sp_only}{entity}")).as_bytes())
        .expect("one idp");
    assert_eq!(md.entity_id, IDP_ENTITY_ID);
    // Two IdPs: ambiguous.
    assert_eq!(
        SamlXmlAdapter
            .parse_metadata(wrap(&format!("{entity}{entity}")).as_bytes())
            .err(),
        Some(SamlXmlReject::Structure)
    );
}

#[test]
fn metadata_refusals() {
    let key = IdpKey::rsa();
    let kd = key_descriptor(Some("signing"), &key.cert_b64());
    let cases = [
        // http SSO URL
        metadata("http://idp.example.test/sso", &kd),
        // not a URL
        metadata("idp.example.test/sso", &kd),
        // no signing certificate
        metadata(
            "https://idp.example.test/sso",
            &key_descriptor(Some("encryption"), &key.cert_b64()),
        ),
        // certificate that is not base64
        metadata(
            "https://idp.example.test/sso",
            &key_descriptor(Some("signing"), "not*base64"),
        ),
        // no HTTP-Redirect SSO service
        metadata("https://idp.example.test/sso", &kd).replace("HTTP-Redirect", "SOAP"),
        // empty entity id
        metadata("https://idp.example.test/sso", &kd)
            .replace(&format!("entityID=\"{IDP_ENTITY_ID}\""), "entityID=\" \""),
        // not metadata
        "<root/>".to_owned(),
    ];
    for xml in cases {
        assert_eq!(
            SamlXmlAdapter.parse_metadata(xml.as_bytes()).err(),
            Some(SamlXmlReject::Structure),
            "{xml}"
        );
    }
    let with_dtd = format!(
        "<!DOCTYPE md>{}",
        metadata("https://idp.example.test/sso", &kd)
    );
    assert_eq!(
        SamlXmlAdapter.parse_metadata(with_dtd.as_bytes()).err(),
        Some(SamlXmlReject::Dtd)
    );
    let huge = vec![b' '; 1024 * 1024 + 1];
    assert_eq!(
        SamlXmlAdapter.parse_metadata(&huge).err(),
        Some(SamlXmlReject::Size)
    );
}

// ---------------------------------------------------------------------------------------------
// HTTP-Redirect encoding
// ---------------------------------------------------------------------------------------------

#[test]
fn encode_redirect_round_trips_through_inflate() {
    let request =
        anvil_core::saml::request::authn_request(&anvil_core::saml::request::AuthnRequestParams {
            sp_entity_id: SP_ENTITY_ID,
            acs_url: ACS_URL,
            destination: "https://idp.example.test/sso",
            request_id: REQUEST_ID,
            issue_instant: now(),
            name_id_format: anvil_core::model::NameIdFormat::EmailAddress,
            force_authn: false,
        });
    let encoded = SamlXmlAdapter.encode_redirect(&request).expect("encode");
    // Standard base64 (not URL-safe, not URL-encoded: the caller does that).
    assert!(
        encoded
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
    );
    let raw = b64std_decode(&encoded).expect("base64");
    let mut inflated = String::new();
    flate2::read::DeflateDecoder::new(&raw[..])
        .read_to_string(&mut inflated)
        .expect("raw deflate");
    assert_eq!(inflated, request);
    // Too large an input is refused.
    assert_eq!(
        SamlXmlAdapter.encode_redirect(&"x".repeat(64 * 1024 + 1)),
        Err(SamlXmlReject::Size)
    );
}
