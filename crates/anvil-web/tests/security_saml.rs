//! D4 attack corpus for the SAML XML adapter (ORG-03). Every input is generated at test time by
//! the test IdP in `saml_support` (keys and certificates included); no private key is committed.
//! Each `saml_rejects_*` test asserts the exact `SamlXmlReject` reason.
//!
//! Signature-wrapping (XSW) cases follow the shapes of Somorovsky et al., "On Breaking SAML: Be
//! Whoever You Want to Be" (USENIX Security 2012) as SAML Raider automates them. Write-ups number
//! them differently, so each test defines its case by structure in its doc comment. In the
//! sketches, `R` is a `samlp:Response`, `A` a `saml:Assertion`, `S` a `ds:Signature`; `*` marks
//! the element the original IdP signature covers, `!` the attacker's forged element.
//!
//! Where it makes the point, a test also runs bergshamra directly on the same document to show
//! that the library alone would accept the signature: those cases are stopped by the adapter's
//! own rules (pinning, pre-check, extraction), not by the cryptography.

mod saml_support;

use std::sync::Mutex;

use anvil_core::model::SamlAssertionData;
use anvil_core::ports::{SamlXml, SamlXmlReject};
use anvil_web::adapters::saml_xml::SamlXmlAdapter;
use bergshamra_dsig::{DsigContext, VerifyResult};
use bergshamra_keys::{KeysManager, loader};
use saml_support::*;

use SamlXmlReject as R;

fn verify(xml: &str, key: &IdpKey) -> Result<SamlAssertionData, SamlXmlReject> {
    SamlXmlAdapter.verify_response(xml.as_bytes(), &[key.cert_pem()])
}

#[track_caller]
fn rejects(xml: &str, key: &IdpKey, reason: SamlXmlReject) {
    assert_eq!(verify(xml, key).err(), Some(reason), "document:\n{xml}");
}

/// What bergshamra alone says about each signature (trusted key only, strict), without the
/// adapter's pre-check, pinning or extraction rules.
fn library_verdicts(xml: &str, key: &IdpKey) -> Vec<bool> {
    let doc = uppsala::Parser::new()
        .with_forbid_dtd(true)
        .parse(xml)
        .expect("parse");
    let mut keys = KeysManager::new();
    keys.add_key(loader::load_x509_cert_pem(key.cert_pem().as_bytes()).expect("cert"));
    let ctx = DsigContext::new(keys)
        .with_trusted_keys_only(true)
        .with_strict_verification(true)
        .with_require_reference_digests(true)
        .with_skip_time_checks(true);
    bergshamra_dsig::verify::verify_all_document_with_source(&ctx, &doc, Some(xml))
        .expect("document-level verification")
        .iter()
        .map(VerifyResult::is_valid)
        .collect()
}

fn forged_opts() -> ResponseOpts {
    ResponseOpts {
        assertion_id: "_forged".into(),
        name_id: "attacker@evil.test".into(),
        ..ResponseOpts::default()
    }
}

/// The attacker's unsigned assertion.
fn forged_assertion() -> String {
    assertion_xml(&forged_opts(), None)
}

/// A signed response (Assertion signed) and its signed Assertion element.
fn signed_parts(key: &IdpKey) -> (String, String) {
    let xml = signed_response(key, &ResponseOpts::default());
    let assertion = element(&xml, "<saml:Assertion", "</saml:Assertion>").to_owned();
    (xml, assertion)
}

/// A Response around `content` (inserted where the Assertion goes).
fn response_around(content: &str) -> String {
    response_xml(&ResponseOpts::default(), None, content)
}

/// `inner` placed right before the closing tag of the element `outer` (a whole element string).
fn nest_inside(outer: &str, close: &str, inner: &str) -> String {
    let at = outer.rfind(close).expect("closing tag");
    format!("{}{inner}{}", &outer[..at], &outer[at..])
}

// =============================================================================================
// Positive controls
// =============================================================================================

/// RSA and ECDSA, Assertion-only and Assertion + Response signatures, all accepted; a response
/// signed only at the Response level is NOT accepted (the Assertion signature is required),
/// although bergshamra alone reports its signature valid.
#[test]
fn saml_accepts_valid_rsa_and_ecdsa_responses() {
    for key in [IdpKey::rsa(), IdpKey::ecdsa()] {
        for sign_response in [false, true] {
            let opts = ResponseOpts {
                sign_response,
                ..ResponseOpts::default()
            };
            let xml = signed_response(&key, &opts);
            let data = verify(&xml, &key).expect("valid response accepted");
            assert_eq!(data.name_id, NAME_ID);
            assert_eq!(data.assertion_id, ASSERTION_ID);
        }
        let response_only = signed_response(
            &key,
            &ResponseOpts {
                sign_assertion: false,
                sign_response: true,
                ..ResponseOpts::default()
            },
        );
        assert_eq!(library_verdicts(&response_only, &key), vec![true]);
        rejects(&response_only, &key, R::SignatureProfile);
    }
}

/// Namespaces are matched by URI, never by prefix: an assertion written with other prefixes
/// (and the default namespace for the Response) verifies.
#[test]
fn saml_accepts_assertion_with_other_prefixes() {
    let key = IdpKey::rsa();
    let opts = ResponseOpts::default();
    let template = assertion_xml(&opts, Some(key.alg))
        .replace("saml:", "a:")
        .replace("xmlns:saml=", "xmlns:a=")
        .replace("ds:", "sig:")
        .replace("xmlns:ds=", "xmlns:sig=");
    let assertion = sign_first(&key, &template);
    let xml = response_xml(&opts, None, &assertion)
        .replace("samlp:", "")
        .replace("xmlns:samlp=", "xmlns=");
    let data = verify(&xml, &key).expect("prefixes do not matter");
    assert_eq!(data.name_id, NAME_ID);
}

/// Claims are read only from the verified Assertion: a NameID, Subject and attributes placed
/// outside it (in `Extensions`) are never read.
#[test]
fn saml_reads_claims_only_from_the_verified_assertion() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let decoy = "<samlp:Extensions><saml:Subject><saml:NameID>attacker@evil.test</saml:NameID></saml:Subject>\
<saml:AttributeStatement><saml:Attribute Name=\"mail\"><saml:AttributeValue>attacker@evil.test</saml:AttributeValue>\
</saml:Attribute></saml:AttributeStatement></samlp:Extensions>";
    let xml = insert_before(&xml, "<samlp:Status>", decoy);
    let data = verify(&xml, &key).expect("decoys outside the assertion are ignored");
    assert_eq!(data.name_id, NAME_ID);
    assert_eq!(data.attributes.get("mail"), Some(&vec![NAME_ID.to_owned()]));
}

// =============================================================================================
// XSW1-XSW8 and other wrapping shapes
// =============================================================================================

/// XSW1: `R!(S[ copy of R's signature, R*(A) ], A!)`. A forged Response whose copied Response
/// signature carries the original signed Response inside it; the forged assertion is the
/// Response child.
#[test]
fn saml_rejects_xsw1_forged_response_wraps_signed_response_in_signature() {
    let key = IdpKey::rsa();
    let original = signed_response(
        &key,
        &ResponseOpts {
            sign_response: true,
            ..ResponseOpts::default()
        },
    );
    let response_sig = element(&original, "<ds:Signature", "</ds:Signature>");
    let wrapped_sig = nest_inside(response_sig, "</ds:Signature>", &original);
    let forged = response_xml(
        &ResponseOpts {
            response_id: "_forged_resp".into(),
            ..forged_opts()
        },
        None,
        &forged_assertion(),
    );
    let xml = insert_before(&forged, "<samlp:Status>", &wrapped_sig);
    rejects(&xml, &key, R::Structure);
}

/// XSW2: `R!(R*(A), S(ref R*), A!)`. As XSW1, but the original signed Response is a detached
/// sibling before the copied signature.
#[test]
fn saml_rejects_xsw2_signed_response_detached_before_signature() {
    let key = IdpKey::rsa();
    let original = signed_response(
        &key,
        &ResponseOpts {
            sign_response: true,
            ..ResponseOpts::default()
        },
    );
    let response_sig = element(&original, "<ds:Signature", "</ds:Signature>").to_owned();
    let forged = response_xml(
        &ResponseOpts {
            response_id: "_forged_resp".into(),
            ..forged_opts()
        },
        None,
        &forged_assertion(),
    );
    let xml = insert_before(
        &forged,
        "<samlp:Status>",
        &format!("{original}{response_sig}"),
    );
    rejects(&xml, &key, R::Structure);
}

/// XSW3: `R(A!, A*(S))`. A cloned, modified assertion (new ID, no signature) inserted before the
/// signed one, both direct Response children.
#[test]
fn saml_rejects_xsw3_cloned_assertion_before_signed() {
    let key = IdpKey::rsa();
    let (_, signed) = signed_parts(&key);
    rejects(
        &response_around(&format!("{}{signed}", forged_assertion())),
        &key,
        R::Structure,
    );
}

/// XSW3 variant: the clone keeps the signed assertion's ID, so a lookup by ID could pick either.
#[test]
fn saml_rejects_xsw3_clone_with_the_signed_id() {
    let key = IdpKey::rsa();
    let (_, signed) = signed_parts(&key);
    let clone = assertion_xml(
        &ResponseOpts {
            name_id: "attacker@evil.test".into(),
            ..ResponseOpts::default()
        },
        None,
    );
    rejects(
        &response_around(&format!("{clone}{signed}")),
        &key,
        R::DuplicateId,
    );
}

/// `R(A*(S), A!)`: the cloned assertion after the signed one.
#[test]
fn saml_rejects_cloned_assertion_after_signed() {
    let key = IdpKey::rsa();
    let (_, signed) = signed_parts(&key);
    rejects(
        &response_around(&format!("{signed}{}", forged_assertion())),
        &key,
        R::Structure,
    );
}

/// XSW4: `R(A!(A*(S)))`. The forged assertion is the Response child and the original signed
/// assertion is nested inside it.
#[test]
fn saml_rejects_xsw4_signed_assertion_wrapped_in_forged_assertion() {
    let key = IdpKey::rsa();
    let (_, signed) = signed_parts(&key);
    let forged = nest_inside(&forged_assertion(), "</saml:Assertion>", &signed);
    rejects(&response_around(&forged), &key, R::Structure);
}

/// XSW5: `R(A!(S copied from A*), A* without S)`. The original signature moved into the forged
/// assertion (which takes the signed ID), the original assertion appended unsigned.
#[test]
fn saml_rejects_xsw5_signature_moved_to_forged_assertion() {
    let key = IdpKey::rsa();
    let (_, signed) = signed_parts(&key);
    let sig = element(&signed, "<ds:Signature", "</ds:Signature>").to_owned();
    let unsigned_original = remove(&signed, &sig);
    let forged = assertion_xml(
        &ResponseOpts {
            name_id: "attacker@evil.test".into(),
            ..ResponseOpts::default()
        },
        None,
    );
    let forged = insert_after(
        &forged,
        &format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>"),
        &sig,
    );
    rejects(
        &response_around(&format!("{forged}{unsigned_original}")),
        &key,
        R::DuplicateId,
    );
    // With a fresh ID on the forged copy the shape is still refused (two assertions).
    let forged_new_id = forged.replace(&format!("ID=\"{ASSERTION_ID}\""), "ID=\"_forged\"");
    rejects(
        &response_around(&format!("{forged_new_id}{unsigned_original}")),
        &key,
        R::Structure,
    );
}

/// XSW6: `R(A!(S(A*)))`. The forged assertion carries the copied signature, and the original
/// signed assertion is nested inside that signature.
#[test]
fn saml_rejects_xsw6_signed_assertion_inside_signature_of_forged() {
    let key = IdpKey::rsa();
    let (_, signed) = signed_parts(&key);
    let sig = element(&signed, "<ds:Signature", "</ds:Signature>").to_owned();
    let sig_with_original = nest_inside(&sig, "</ds:Signature>", &signed);
    let forged = insert_after(
        &forged_assertion(),
        &format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>"),
        &sig_with_original,
    );
    rejects(&response_around(&forged), &key, R::Structure);
}

/// XSW7: `R(Extensions(A*(S)), A!)`. The signed assertion wrapped in `samlp:Extensions`, the
/// forged assertion as the Response child.
#[test]
fn saml_rejects_xsw7_signed_assertion_wrapped_in_extensions() {
    let key = IdpKey::rsa();
    let (_, signed) = signed_parts(&key);
    let xml = insert_before(
        &response_around(&forged_assertion()),
        "<samlp:Status>",
        &format!("<samlp:Extensions>{signed}</samlp:Extensions>"),
    );
    rejects(&xml, &key, R::Structure);
}

/// XSW8: `R(A!(S(Object(A*))))`. The original signed assertion inside a `ds:Object` of the
/// signature the forged assertion carries.
#[test]
fn saml_rejects_xsw8_signed_assertion_in_signature_object() {
    let key = IdpKey::rsa();
    let (_, signed) = signed_parts(&key);
    let sig = element(&signed, "<ds:Signature", "</ds:Signature>").to_owned();
    let sig_with_object = nest_inside(
        &sig,
        "</ds:Signature>",
        &format!("<ds:Object>{signed}</ds:Object>"),
    );
    let forged = insert_after(
        &forged_assertion(),
        &format!("<saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>"),
        &sig_with_object,
    );
    rejects(&response_around(&forged), &key, R::Structure);
}

/// `R(A!(Subject(SubjectConfirmation(SubjectConfirmationData(A*)))))`: the signed assertion
/// hidden in the forged assertion's SubjectConfirmationData.
#[test]
fn saml_rejects_signed_assertion_in_subject_confirmation_data() {
    let key = IdpKey::rsa();
    let (_, signed) = signed_parts(&key);
    let forged = forged_assertion();
    let scd = element(&forged, "<saml:SubjectConfirmationData", "/>").to_owned();
    let wrapped = format!(
        "{}>{signed}</saml:SubjectConfirmationData>",
        &scd[..scd.len() - 2]
    );
    let forged = replace_once(&forged, &scd, &wrapped);
    rejects(&response_around(&forged), &key, R::Structure);
}

/// `R(A!(Advice(A*)))`: the signed assertion in the forged assertion's `Advice`.
#[test]
fn saml_rejects_signed_assertion_in_advice() {
    let key = IdpKey::rsa();
    let (_, signed) = signed_parts(&key);
    let forged = insert_before(
        &forged_assertion(),
        "<saml:AuthnStatement",
        &format!("<saml:Advice>{signed}</saml:Advice>"),
    );
    rejects(&response_around(&forged), &key, R::Structure);
}

/// `R(S(ref A), A)`: the assertion signature moved out to a sibling position (a Response
/// child). The assertion itself is then unsigned.
#[test]
fn saml_rejects_signature_moved_to_sibling() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let sig = assertion_signature(&xml).to_owned();
    let moved = insert_before(&remove(&xml, &sig), "<samlp:Status>", &sig);
    rejects(&moved, &key, R::SignatureProfile);
}

/// Pinned location: the assertion signature moved to the end of the assertion. The enveloped
/// transform still removes it, so bergshamra alone reports it valid; the adapter requires it
/// right after the Issuer.
#[test]
fn saml_rejects_assertion_signature_not_after_issuer() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let sig = assertion_signature(&xml).to_owned();
    let moved = insert_before(&remove(&xml, &sig), "</saml:Assertion>", &sig);
    assert_eq!(library_verdicts(&moved, &key), vec![true]);
    rejects(&moved, &key, R::SignatureProfile);
}

/// Pinned location: a Response signature that is not right after the Response Issuer.
#[test]
fn saml_rejects_response_signature_out_of_place() {
    let key = IdpKey::rsa();
    let xml = signed_response(
        &key,
        &ResponseOpts {
            sign_response: true,
            ..ResponseOpts::default()
        },
    );
    let sig = element(&xml, "<ds:Signature", "</ds:Signature>").to_owned();
    let status = element(&xml, "<samlp:Status>", "</samlp:Status>").to_owned();
    let moved = insert_after(&remove(&xml, &sig), &status, &sig);
    rejects(&moved, &key, R::SignatureProfile);
}

/// Stray signatures: a copy of a valid signature anywhere else in the document (here in
/// `Extensions`) is refused, so the library never chooses among signatures.
#[test]
fn saml_rejects_stray_signature_in_extensions() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let sig = assertion_signature(&xml).to_owned();
    let xml = insert_before(
        &xml,
        "<samlp:Status>",
        &format!("<samlp:Extensions>{sig}</samlp:Extensions>"),
    );
    rejects(&xml, &key, R::SignatureProfile);
}

/// Two signatures directly in the Response.
#[test]
fn saml_rejects_two_response_signatures() {
    let key = IdpKey::rsa();
    let xml = signed_response(
        &key,
        &ResponseOpts {
            sign_response: true,
            ..ResponseOpts::default()
        },
    );
    let sig = element(&xml, "<ds:Signature", "</ds:Signature>").to_owned();
    let doubled = replace_once(&xml, &sig, &format!("{sig}{sig}"));
    rejects(&doubled, &key, R::SignatureProfile);
}

/// Overly broad signature lookup: a validly IdP-signed foreign element (signed metadata) in
/// `Extensions`, with the forged assertion unsigned. bergshamra alone reports the foreign
/// signature valid.
#[test]
fn saml_rejects_foreign_signed_element_in_extensions() {
    let key = IdpKey::rsa();
    let template = format!(
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_md1\" entityID=\"{IDP_ENTITY_ID}\">{}</md:EntityDescriptor>",
        signature_template(key.alg, "_md1")
    );
    let signed_md = sign_first(&key, &template);
    let xml = insert_before(
        &response_around(&forged_assertion()),
        "<samlp:Status>",
        &format!("<samlp:Extensions>{signed_md}</samlp:Extensions>"),
    );
    assert_eq!(library_verdicts(&xml, &key), vec![true]);
    rejects(&xml, &key, R::SignatureProfile);
}

// =============================================================================================
// Signature exclusion and key injection
// =============================================================================================

#[test]
fn saml_rejects_unsigned_assertion() {
    let key = IdpKey::rsa();
    let xml = signed_response(
        &key,
        &ResponseOpts {
            sign_assertion: false,
            ..ResponseOpts::default()
        },
    );
    assert!(!xml.contains("Signature"));
    rejects(&xml, &key, R::SignatureProfile);
}

#[test]
fn saml_rejects_signed_response_with_unsigned_assertion() {
    let key = IdpKey::ecdsa();
    let xml = signed_response(
        &key,
        &ResponseOpts {
            sign_assertion: false,
            sign_response: true,
            ..ResponseOpts::default()
        },
    );
    rejects(&xml, &key, R::SignatureProfile);
}

#[test]
fn saml_rejects_empty_signature_value() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let value = element(&xml, "<ds:SignatureValue>", "</ds:SignatureValue>").to_owned();
    let xml = replace_once(&xml, &value, "<ds:SignatureValue></ds:SignatureValue>");
    rejects(&xml, &key, R::SignatureProfile);
}

#[test]
fn saml_rejects_empty_digest_value() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let value = element(&xml, "<ds:DigestValue>", "</ds:DigestValue>").to_owned();
    let xml = replace_once(&xml, &value, "<ds:DigestValue> </ds:DigestValue>");
    rejects(&xml, &key, R::SignatureProfile);
}

/// Key injection: the attacker signs a forged response with its own key and embeds its
/// certificate in KeyInfo. Only the configured certificate is trusted.
#[test]
fn saml_rejects_keyinfo_key_injection() {
    let trusted = IdpKey::rsa();
    let attacker = IdpKey::rsa();
    let xml = signed_response(&attacker, &forged_opts());
    assert!(xml.contains(&attacker.cert_b64()[..48]));
    rejects(&xml, &trusted, R::UntrustedKey);
    // Control: the same document is accepted when the attacker's cert is the configured one.
    verify(&xml, &attacker).expect("control");
}

/// KeyInfo may only carry hints (X509Data / KeyName): a RetrievalMethod (which could point at
/// external or local resources) is refused before verification.
#[test]
fn saml_rejects_keyinfo_retrieval_method() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let xml = insert_after(
        &xml,
        "<ds:KeyInfo>",
        "<ds:RetrievalMethod URI=\"cert.der\" Type=\"http://www.w3.org/2000/09/xmldsig#rawX509Certificate\"/>",
    );
    rejects(&xml, &key, R::SignatureProfile);
}

/// A changed value inside the signed assertion breaks its digest.
#[test]
fn saml_rejects_tampered_assertion() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let xml = replace_once(
        &xml,
        &format!(">{NAME_ID}</saml:NameID>"),
        ">alicf@example.test</saml:NameID>",
    );
    rejects(&xml, &key, R::Signature);
}

/// A present Response signature must verify too, even when the Assertion signature is valid.
#[test]
fn saml_rejects_invalid_response_signature() {
    let key = IdpKey::rsa();
    let xml = signed_response(
        &key,
        &ResponseOpts {
            sign_response: true,
            ..ResponseOpts::default()
        },
    );
    let xml = replace_once(
        &xml,
        &format!("Destination=\"{ACS_URL}\""),
        "Destination=\"https://evil.example.test/acs\"",
    );
    assert_eq!(library_verdicts(&xml, &key), vec![false, true]);
    rejects(&xml, &key, R::Signature);
}

// =============================================================================================
// Comment injection (signature stays valid: c14n drops comments)
// =============================================================================================

/// `alice@example.test<!---->.evil.test`: the IdP signed `alice@example.test.evil.test`; a
/// reader taking the first text node would see `alice@example.test`. The signature still
/// verifies (bergshamra alone says valid), the adapter refuses the NameID.
#[test]
fn saml_rejects_comment_in_name_id() {
    let key = IdpKey::rsa();
    let opts = ResponseOpts {
        name_id: "alice@example.test.evil.test".into(),
        ..ResponseOpts::default()
    };
    let xml = signed_response(&key, &opts);
    let xml = replace_once(
        &xml,
        ">alice@example.test.evil.test</saml:NameID>",
        ">alice@example.test<!---->.evil.test</saml:NameID>",
    );
    assert_eq!(library_verdicts(&xml, &key), vec![true]);
    rejects(&xml, &key, R::Structure);
}

#[test]
fn saml_rejects_comment_in_attribute_value() {
    let key = IdpKey::rsa();
    let opts = ResponseOpts {
        attributes: vec![(
            "mail".into(),
            None,
            vec!["alice@example.test.evil.test".into()],
        )],
        ..ResponseOpts::default()
    };
    let xml = signed_response(&key, &opts);
    let xml = replace_once(
        &xml,
        ">alice@example.test.evil.test</saml:AttributeValue>",
        ">alice@example.test<!-- -->.evil.test</saml:AttributeValue>",
    );
    assert_eq!(library_verdicts(&xml, &key), vec![true]);
    rejects(&xml, &key, R::Structure);
}

/// A child element inside the NameID (signed that way by the IdP) is refused too.
#[test]
fn saml_rejects_element_in_name_id() {
    let key = IdpKey::rsa();
    let opts = ResponseOpts::default();
    let template = replace_once(
        &assertion_xml(&opts, Some(key.alg)),
        &format!(">{NAME_ID}</saml:NameID>"),
        ">alice<saml:x>@evil.test</saml:x></saml:NameID>",
    );
    let xml = response_xml(&opts, None, &sign_first(&key, &template));
    rejects(&xml, &key, R::Structure);
}

// =============================================================================================
// Parser differentials, DTDs and entities
// =============================================================================================

#[test]
fn saml_rejects_doctype_without_entities() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    rejects(&format!("<!DOCTYPE samlp:Response>{xml}"), &key, R::Dtd);
}

#[test]
fn saml_rejects_billion_laughs() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let mut dtd = String::from("<!DOCTYPE r [<!ENTITY l0 \"lol\">");
    for i in 1..10 {
        let refs = format!("&l{};", i - 1).repeat(10);
        dtd.push_str(&format!("<!ENTITY l{i} \"{refs}\">"));
    }
    dtd.push_str("]>");
    let xml = replace_once(
        &xml,
        &format!(">{NAME_ID}</saml:NameID>"),
        ">&l9;</saml:NameID>",
    );
    rejects(&format!("{dtd}{xml}"), &key, R::Dtd);
}

#[test]
fn saml_rejects_external_entity() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let xml = replace_once(
        &xml,
        &format!(">{NAME_ID}</saml:NameID>"),
        ">&xxe;</saml:NameID>",
    );
    rejects(
        &format!("<!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]>{xml}"),
        &key,
        R::Dtd,
    );
    // A parameter entity pulling an external DTD.
    let (xml, _) = signed_parts(&key);
    rejects(
        &format!(
            "<!DOCTYPE r [<!ENTITY % ext SYSTEM \"https://evil.example.test/x.dtd\"> %ext;]>{xml}"
        ),
        &key,
        R::Dtd,
    );
}

/// A forged `saml:Assertion` whose `saml` prefix is bound to another namespace URI, before the
/// real signed assertion: by URI it is not an Assertion, and the Response may not carry it.
#[test]
fn saml_rejects_redefined_saml_prefix() {
    let key = IdpKey::rsa();
    let (_, signed) = signed_parts(&key);
    let fake = forged_assertion().replace(
        &format!("xmlns:saml=\"{NS_ASSERTION}\""),
        "xmlns:saml=\"urn:evil:assertion\"",
    );
    rejects(
        &response_around(&format!("{fake}{signed}")),
        &key,
        R::Structure,
    );
}

/// The assertion's `ds:Signature` with `ds` rebound: by namespace URI it is not an XML-DSig
/// signature but an unknown element inside the Assertion.
#[test]
fn saml_rejects_redefined_ds_prefix() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let xml = replace_once(
        &xml,
        &format!("<ds:Signature xmlns:ds=\"{NS_DSIG}\">"),
        "<ds:Signature xmlns:ds=\"urn:evil:dsig\">",
    );
    rejects(&xml, &key, R::Structure);
}

/// An unprefixed `Assertion` in a foreign default namespace is not an Assertion either.
#[test]
fn saml_rejects_default_namespace_trick() {
    let key = IdpKey::rsa();
    let (_, signed) = signed_parts(&key);
    let fake = "<Assertion xmlns=\"urn:evil\" ID=\"_x\"><Issuer>x</Issuer></Assertion>";
    rejects(
        &response_around(&format!("{fake}{signed}")),
        &key,
        R::Structure,
    );
}

/// Attribute pollution: `ID` and `samlp:ID` on the same element (a reader by local name and a
/// reader by qualified name see different ids).
#[test]
fn saml_rejects_attribute_pollution_prefixed_id() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let polluted = replace_once(
        &xml,
        &format!("ID=\"{ASSERTION_ID}\""),
        &format!("samlp:ID=\"_forged\" ID=\"{ASSERTION_ID}\""),
    );
    rejects(&polluted, &key, R::Structure);
    let polluted = replace_once(
        &xml,
        &format!("ID=\"{RESPONSE_ID}\""),
        &format!("ID=\"{RESPONSE_ID}\" saml:ID=\"_other\""),
    );
    rejects(&polluted, &key, R::Structure);
}

/// Void canonicalization: a relative namespace URI on an element inside the signed assertion
/// must be an error, never a digest over empty input.
#[test]
fn saml_rejects_void_canonicalization_relative_namespace() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let on_element = replace_once(&xml, "<saml:Subject>", "<saml:Subject xmlns:v=\"void\">");
    rejects(&on_element, &key, R::Structure);
    let default_ns = replace_once(
        &xml,
        "<saml:AttributeStatement>",
        "<saml:AttributeStatement xmlns=\"relative/ns\">",
    );
    rejects(&default_ns, &key, R::Structure);
}

/// Void canonicalization in a transform: a relative namespace URI declared on the exc-c14n
/// Transform element.
#[test]
fn saml_rejects_void_canonicalization_in_transform() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let xml = replace_once(
        &xml,
        &format!("<ds:Transform Algorithm=\"{EXC_C14N}\"/>"),
        &format!("<ds:Transform xmlns:ec=\"void\" Algorithm=\"{EXC_C14N}\"/>"),
    );
    rejects(&xml, &key, R::Structure);
}

#[test]
fn saml_rejects_processing_instruction() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let xml = insert_after(&xml, "<saml:Subject>", "<?xml-stylesheet href=\"x\"?>");
    rejects(&xml, &key, R::Structure);
}

// =============================================================================================
// Algorithm downgrade and signature profile
// =============================================================================================

fn with_signed_info_change(from: &str, to: &str) -> (IdpKey, String) {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let xml = replace_once(&xml, from, to);
    (key, xml)
}

#[test]
fn saml_rejects_sha1_signature_method() {
    let (key, xml) = with_signed_info_change(RSA_SHA256, RSA_SHA1);
    rejects(&xml, &key, R::Algorithm);
}

#[test]
fn saml_rejects_sha1_digest() {
    let (key, xml) = with_signed_info_change(DIGEST_SHA256, DIGEST_SHA1);
    rejects(&xml, &key, R::Algorithm);
}

#[test]
fn saml_rejects_hmac_signature_method() {
    let (key, xml) = with_signed_info_change(RSA_SHA256, HMAC_SHA256);
    rejects(&xml, &key, R::Algorithm);
}

#[test]
fn saml_rejects_c14n_with_comments() {
    let (key, xml) = with_signed_info_change(
        &format!("<ds:CanonicalizationMethod Algorithm=\"{EXC_C14N}\"/>"),
        &format!("<ds:CanonicalizationMethod Algorithm=\"{EXC_C14N_COMMENTS}\"/>"),
    );
    rejects(&xml, &key, R::Algorithm);
}

#[test]
fn saml_rejects_inclusive_c14n() {
    let (key, xml) = with_signed_info_change(
        &format!("<ds:CanonicalizationMethod Algorithm=\"{EXC_C14N}\"/>"),
        &format!("<ds:CanonicalizationMethod Algorithm=\"{C14N_10}\"/>"),
    );
    rejects(&xml, &key, R::Algorithm);
}

#[test]
fn saml_rejects_xpath_transform() {
    let (key, xml) = with_signed_info_change(
        &format!("<ds:Transform Algorithm=\"{EXC_C14N}\"/>"),
        &format!(
            "<ds:Transform Algorithm=\"{XPATH}\"><ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath></ds:Transform>"
        ),
    );
    rejects(&xml, &key, R::Algorithm);
}

#[test]
fn saml_rejects_xslt_transform() {
    let (key, xml) = with_signed_info_change(
        &format!("<ds:Transform Algorithm=\"{EXC_C14N}\"/>"),
        &format!(
            "<ds:Transform Algorithm=\"{XSLT}\"><xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" version=\"1.0\"/></ds:Transform>"
        ),
    );
    rejects(&xml, &key, R::Algorithm);
}

#[test]
fn saml_rejects_extra_transform() {
    let (key, xml) = with_signed_info_change(
        &format!("<ds:Transform Algorithm=\"{EXC_C14N}\"/>"),
        &format!(
            "<ds:Transform Algorithm=\"{EXC_C14N}\"/><ds:Transform Algorithm=\"{ENVELOPED}\"/>"
        ),
    );
    rejects(&xml, &key, R::SignatureProfile);
}

#[test]
fn saml_rejects_missing_transform() {
    let (key, xml) =
        with_signed_info_change(&format!("<ds:Transform Algorithm=\"{EXC_C14N}\"/>"), "");
    rejects(&xml, &key, R::SignatureProfile);
}

#[test]
fn saml_rejects_reordered_transforms() {
    let (key, xml) = with_signed_info_change(
        &format!(
            "<ds:Transform Algorithm=\"{ENVELOPED}\"/><ds:Transform Algorithm=\"{EXC_C14N}\"/>"
        ),
        &format!(
            "<ds:Transform Algorithm=\"{EXC_C14N}\"/><ds:Transform Algorithm=\"{ENVELOPED}\"/>"
        ),
    );
    rejects(&xml, &key, R::SignatureProfile);
}

#[test]
fn saml_rejects_reference_uri_empty() {
    let (key, xml) = with_signed_info_change(&format!("URI=\"#{ASSERTION_ID}\""), "URI=\"\"");
    rejects(&xml, &key, R::SignatureProfile);
}

#[test]
fn saml_rejects_reference_to_another_element() {
    // The assertion signature pointing at the Response.
    let (key, xml) = with_signed_info_change(
        &format!("URI=\"#{ASSERTION_ID}\""),
        &format!("URI=\"#{RESPONSE_ID}\""),
    );
    rejects(&xml, &key, R::SignatureProfile);
}

#[test]
fn saml_rejects_reference_uri_external_url() {
    let (key, xml) = with_signed_info_change(
        &format!("URI=\"#{ASSERTION_ID}\""),
        "URI=\"https://evil.example.test/assertion.xml\"",
    );
    rejects(&xml, &key, R::SignatureProfile);
}

#[test]
fn saml_rejects_two_references() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let reference = element(&xml, "<ds:Reference ", "</ds:Reference>").to_owned();
    let xml = replace_once(&xml, &reference, &format!("{reference}{reference}"));
    rejects(&xml, &key, R::SignatureProfile);
}

#[test]
fn saml_rejects_signature_object() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let xml = insert_before(&xml, "</ds:Signature>", "<ds:Object>x</ds:Object>");
    rejects(&xml, &key, R::SignatureProfile);
}

static CWD_LOCK: Mutex<()> = Mutex::new(());

/// Restores the working directory when dropped.
struct CwdGuard(std::path::PathBuf);

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
    }
}

/// No local file reference resolution. bergshamra resolves a non-fragment Reference URI as a
/// file relative to the process working directory. With a file at that relative path in a temp
/// working directory, the adapter refuses at the pre-check (SignatureProfile), before any
/// library call: a library-level failure would be `Signature`. Control: bergshamra alone does
/// read the file (a signature over it verifies only while the file exists).
#[test]
fn saml_rejects_reference_uri_relative_file() {
    let _lock = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let attacked = replace_once(
        &xml,
        &format!("URI=\"#{ASSERTION_ID}\""),
        "URI=\"evidence.xml\"",
    );

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("evidence.xml"),
        b"<evidence>signed bytes</evidence>",
    )
    .expect("write");
    let _guard = CwdGuard(std::env::current_dir().expect("cwd"));
    std::env::set_current_dir(dir.path()).expect("chdir");

    rejects(&attacked, &key, R::SignatureProfile);

    // Control: a signature whose only Reference is the relative file (no transforms), made by
    // the trusted key in this working directory, is valid for bergshamra alone ...
    let opts = ResponseOpts::default();
    let file_template = replace_once(
        &assertion_xml(&opts, Some(key.alg)),
        &format!(
            "URI=\"#{ASSERTION_ID}\"><ds:Transforms><ds:Transform Algorithm=\"{ENVELOPED}\"/><ds:Transform Algorithm=\"{EXC_C14N}\"/></ds:Transforms>"
        ),
        "URI=\"evidence.xml\">",
    );
    let file_signed = response_xml(&opts, None, &sign_first(&key, &file_template));
    assert_eq!(
        library_verdicts(&file_signed, &key),
        vec![true],
        "library reads the file"
    );
    // ... and the adapter refuses it without reading anything.
    rejects(&file_signed, &key, R::SignatureProfile);
    // ... and it stops verifying for the library once the file is gone.
    std::fs::remove_file(dir.path().join("evidence.xml")).expect("rm");
    assert_eq!(library_verdicts(&file_signed, &key), vec![false]);
}

// =============================================================================================
// Structure: ids, assertions, encryption, size
// =============================================================================================

#[test]
fn saml_rejects_duplicate_ids() {
    let key = IdpKey::rsa();
    // The Response and the Assertion share an id.
    let opts = ResponseOpts {
        response_id: ASSERTION_ID.into(),
        ..ResponseOpts::default()
    };
    rejects(&signed_response(&key, &opts), &key, R::DuplicateId);
    // An element in Extensions carries the assertion's id.
    let (xml, _) = signed_parts(&key);
    let xml = insert_before(
        &xml,
        "<samlp:Status>",
        &format!("<samlp:Extensions><x ID=\"{ASSERTION_ID}\"/></samlp:Extensions>"),
    );
    rejects(&xml, &key, R::DuplicateId);
    // Another id attribute name bergshamra registers (`Id`, `AssertionID`, `xml:id`).
    let (xml, _) = signed_parts(&key);
    for attr in ["Id", "AssertionID", "xml:id"] {
        let dup = insert_before(
            &xml,
            "<samlp:Status>",
            &format!("<samlp:Extensions><x {attr}=\"{ASSERTION_ID}\"/></samlp:Extensions>"),
        );
        rejects(&dup, &key, R::DuplicateId);
    }
}

/// Two validly signed assertions (different ids) in one Response.
#[test]
fn saml_rejects_second_assertion() {
    let key = IdpKey::rsa();
    let (_, first) = signed_parts(&key);
    let second = signed_assertion(
        &key,
        &ResponseOpts {
            assertion_id: "_assert2".into(),
            ..ResponseOpts::default()
        },
    );
    let xml = response_around(&format!("{first}{second}"));
    assert_eq!(library_verdicts(&xml, &key), vec![true, true]);
    rejects(&xml, &key, R::Structure);
}

#[test]
fn saml_rejects_encrypted_assertion() {
    let key = IdpKey::rsa();
    let encrypted = "<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\
<xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>";
    rejects(&response_around(encrypted), &key, R::Encrypted);
    // Next to a signed assertion, too.
    let (xml, _) = signed_parts(&key);
    let xml = insert_before(&xml, "<saml:Assertion", encrypted);
    rejects(&xml, &key, R::Encrypted);
}

#[test]
fn saml_rejects_encrypted_id() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let name_id = element(&xml, "<saml:NameID", "</saml:NameID>").to_owned();
    let xml = replace_once(
        &xml,
        &name_id,
        "<saml:EncryptedID><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></saml:EncryptedID>",
    );
    rejects(&xml, &key, R::Encrypted);
}

#[test]
fn saml_rejects_wrong_root_or_version() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    rejects(
        &replace_once(
            &xml,
            &format!("ID=\"{RESPONSE_ID}\" Version=\"2.0\""),
            &format!("ID=\"{RESPONSE_ID}\" Version=\"1.1\""),
        ),
        &key,
        R::Structure,
    );
    let other_root = xml
        .replace("<samlp:Response ", "<samlp:LogoutResponse ")
        .replace("</samlp:Response>", "</samlp:LogoutResponse>");
    rejects(&other_root, &key, R::Structure);
}

#[test]
fn saml_rejects_unknown_response_child() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    rejects(
        &insert_before(&xml, "<saml:Assertion", "<x:Evil xmlns:x=\"urn:x\"/>"),
        &key,
        R::Structure,
    );
}

#[test]
fn saml_rejects_deep_nesting() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let deep = format!(
        "<samlp:Extensions>{}{}</samlp:Extensions>",
        "<d>".repeat(80),
        "</d>".repeat(80)
    );
    rejects(
        &insert_before(&xml, "<samlp:Status>", &deep),
        &key,
        R::Parse,
    );
}

#[test]
fn saml_rejects_oversized_response() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let big = format!(
        "<samlp:Extensions><x>{}</x></samlp:Extensions>",
        "A".repeat(256 * 1024)
    );
    rejects(&insert_before(&xml, "<samlp:Status>", &big), &key, R::Size);
}

/// Many small elements under the byte cap: the markup cap bounds the node count before parsing.
#[test]
fn saml_rejects_markup_flood() {
    let key = IdpKey::rsa();
    let (xml, _) = signed_parts(&key);
    let flood = format!(
        "<samlp:Extensions>{}</samlp:Extensions>",
        "<x/>".repeat(20_000)
    );
    let xml = insert_before(&xml, "<samlp:Status>", &flood);
    assert!(xml.len() < 256 * 1024);
    rejects(&xml, &key, R::Size);
}
