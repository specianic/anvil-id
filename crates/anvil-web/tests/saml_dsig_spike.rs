//! D4 spike (06-01): bergshamra-dsig signs and verifies a minimal SAML assertion on the aws-lc
//! provider alone, with uppsala as the only XML parser and keys that come from configuration only.
//!
//! Every key and certificate is generated at test time with aws-lc-rs; nothing secret is committed.
//! The SAML adapter itself (profile pre-check, extraction, attack corpus) is 06-09; this file only
//! proves the library calls that adapter will make.

use anvil_jose::encoding::b64std;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PKCS1_SHA256,
};
use bergshamra_dsig::{DsigContext, VerifyResult};
use bergshamra_keys::{Key, KeysManager, loader};
use uppsala::{Document, NodeId};

// Algorithm URIs (XML-DSig / XML-DSig-more / exc-c14n).
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

// ---------------------------------------------------------------------------------------------
// Test-time key material: aws-lc-rs keys and a minimal self-signed X.509 v3 certificate.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Alg {
    Rsa,
    Ecdsa,
}

impl Alg {
    fn signature_method(self) -> &'static str {
        match self {
            Alg::Rsa => RSA_SHA256,
            Alg::Ecdsa => ECDSA_SHA256,
        }
    }
}

/// One generated signer: PKCS#8 private key (DER, memory only) and its self-signed certificate.
struct TestSigner {
    pkcs8: Vec<u8>,
    cert_der: Vec<u8>,
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let bytes: Vec<u8> = len
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut chunk = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            chunk.insert(0, 0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        body.extend(chunk);
    }
    tlv(0x06, &body)
}

fn name(common_name: &str) -> Vec<u8> {
    let atv = seq(&[&oid(&[2, 5, 4, 3]), &tlv(0x0c, common_name.as_bytes())]);
    seq(&[&tlv(0x31, &atv)])
}

fn self_signed_cert(
    alg: Alg,
    common_name: &str,
    spki: &[u8],
    sign: impl Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let sig_alg = match alg {
        // sha256WithRSAEncryption, NULL parameters
        Alg::Rsa => seq(&[&oid(&[1, 2, 840, 113549, 1, 1, 11]), &[0x05, 0x00]]),
        // ecdsa-with-SHA256, absent parameters
        Alg::Ecdsa => seq(&[&oid(&[1, 2, 840, 10045, 4, 3, 2])]),
    };
    let subject = name(common_name);
    let validity = seq(&[&tlv(0x17, b"250101000000Z"), &tlv(0x17, b"491231235959Z")]);
    let tbs = seq(&[
        &tlv(0xa0, &tlv(0x02, &[0x02])), // [0] version v3
        &tlv(0x02, &[0x01, 0x23, 0x45]), // serial
        &sig_alg,
        &subject,
        &validity,
        &subject,
        spki,
    ]);
    let mut bits = vec![0x00];
    bits.extend(sign(&tbs));
    seq(&[&tbs, &sig_alg, &tlv(0x03, &bits)])
}

fn generate(alg: Alg, common_name: &str) -> TestSigner {
    let rng = SystemRandom::new();
    match alg {
        Alg::Rsa => {
            let kp = RsaKeyPair::generate(KeySize::Rsa2048).expect("rsa keygen");
            let pkcs8 = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&kp).expect("pkcs8");
            let spki = kp.public_key().as_der().expect("spki");
            let cert_der = self_signed_cert(alg, common_name, spki.as_ref(), |tbs| {
                let mut sig = vec![0u8; kp.public_modulus_len()];
                kp.sign(&RSA_PKCS1_SHA256, &rng, tbs, &mut sig)
                    .expect("rsa sign");
                sig
            });
            TestSigner {
                pkcs8: pkcs8.as_ref().to_vec(),
                cert_der,
            }
        }
        Alg::Ecdsa => {
            let kp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("ec keygen");
            let pkcs8 = kp.to_pkcs8v1().expect("pkcs8");
            let spki = kp.public_key().as_der().expect("spki");
            let cert_der = self_signed_cert(alg, common_name, spki.as_ref(), |tbs| {
                kp.sign(&rng, tbs).expect("ec sign").as_ref().to_vec()
            });
            TestSigner {
                pkcs8: pkcs8.as_ref().to_vec(),
                cert_der,
            }
        }
    }
}

/// PEM-armour DER bytes in memory (64-column base64 lines, as pem-rfc7468 requires).
fn pem(label: &str, der: &[u8]) -> String {
    let b64 = b64std(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

impl TestSigner {
    /// The IdP signing certificate as an operator would paste it into the connection config.
    fn cert_pem(&self) -> String {
        pem("CERTIFICATE", &self.cert_der)
    }

    /// Signing key for the test-only IdP, carrying its certificate so `<ds:X509Data/>` is filled.
    fn signing_key(&self, alg: Alg) -> Key {
        // The PKCS#8 label is assembled at runtime; the key exists only in memory for this test.
        let label = ["PRIVATE", "KEY"].join(" ");
        let pem = pem(&label, &self.pkcs8);
        let mut key = match alg {
            Alg::Rsa => loader::load_rsa_private_pem(pem.as_bytes()),
            Alg::Ecdsa => loader::load_ec_p256_private_pem(pem.as_bytes()),
        }
        .expect("load generated private key");
        key.x509_chain = vec![self.cert_der.clone()];
        key
    }
}

// ---------------------------------------------------------------------------------------------
// SAML fixture, signer and verifier (the calls 06-09 will make).
// ---------------------------------------------------------------------------------------------

/// Minimal `samlp:Response` with one `saml:Assertion ID="_a1"` carrying an enveloped signature
/// template (exc-c14n, RSA/ECDSA-SHA256, `Reference URI="#_a1"`) after the Issuer, as SAML requires.
fn response_template(alg: Alg) -> String {
    let sig_method = alg.signature_method();
    format!(
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r1\" Version=\"2.0\" \
IssueInstant=\"2026-11-26T10:00:00Z\" Destination=\"https://sp.example.test/acs\">\
<saml:Issuer>https://idp.example.test</saml:Issuer>\
<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>\
<saml:Assertion ID=\"_a1\" Version=\"2.0\" IssueInstant=\"2026-11-26T10:00:00Z\">\
<saml:Issuer>https://idp.example.test</saml:Issuer>\
<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
<ds:SignedInfo>\
<ds:CanonicalizationMethod Algorithm=\"{EXC_C14N}\"/>\
<ds:SignatureMethod Algorithm=\"{sig_method}\"/>\
<ds:Reference URI=\"#_a1\">\
<ds:Transforms>\
<ds:Transform Algorithm=\"{ENVELOPED}\"/>\
<ds:Transform Algorithm=\"{EXC_C14N}\"/>\
</ds:Transforms>\
<ds:DigestMethod Algorithm=\"{DIGEST_SHA256}\"/>\
<ds:DigestValue></ds:DigestValue>\
</ds:Reference>\
</ds:SignedInfo>\
<ds:SignatureValue></ds:SignatureValue>\
<ds:KeyInfo><ds:X509Data/></ds:KeyInfo>\
</ds:Signature>\
<saml:Subject><saml:NameID>alice@example.test</saml:NameID></saml:Subject>\
<saml:AttributeStatement><saml:Attribute Name=\"email\">\
<saml:AttributeValue>alice@example.test</saml:AttributeValue>\
</saml:Attribute></saml:AttributeStatement>\
</saml:Assertion>\
</samlp:Response>"
    )
}

/// Test-only IdP: sign the template with the given signer.
fn sign_response(alg: Alg, signer: &TestSigner) -> String {
    let mut keys = KeysManager::new();
    keys.add_key(signer.signing_key(alg));
    let ctx = DsigContext::new(keys);
    let signed = bergshamra_dsig::sign::sign(&ctx, &response_template(alg)).expect("sign");
    assert!(!signed.contains("<ds:SignatureValue></ds:SignatureValue>"));
    assert!(!signed.contains("<ds:DigestValue></ds:DigestValue>"));
    signed
}

/// The one parser: uppsala with DTDs forbidden.
fn parse(xml: &str) -> Document<'_> {
    uppsala::Parser::new()
        .with_forbid_dtd(true)
        .with_max_depth(64)
        .parse(xml)
        .expect("parse")
}

fn assertion_node(doc: &Document<'_>) -> NodeId {
    let root = doc.document_element().expect("root");
    doc.children(root)
        .into_iter()
        .find(|n| {
            doc.element(*n)
                .is_some_and(|e| e.name.local_name.as_ref() == "Assertion")
        })
        .expect("assertion")
}

/// SP side: verify with a context that trusts only the configured certificate(s).
fn verify(xml: &str, trusted_cert_pems: &[String]) -> (Vec<VerifyResult>, NodeId) {
    let doc = parse(xml);
    let mut keys = KeysManager::new();
    for cert in trusted_cert_pems {
        keys.add_key(loader::load_x509_cert_pem(cert.as_bytes()).expect("load trusted cert"));
    }
    let ctx = DsigContext::new(keys)
        .with_trusted_keys_only(true)
        .with_strict_verification(true)
        .with_require_reference_digests(true)
        .with_skip_time_checks(true);
    let results = bergshamra_dsig::verify::verify_all_document_with_source(&ctx, &doc, Some(xml))
        .expect("document-level verification");
    (results, assertion_node(&doc))
}

fn assert_assertion_verified(alg: Alg) {
    let signer = generate(alg, "Spike IdP");
    let signed = sign_response(alg, &signer);
    let (results, assertion) = verify(&signed, &[signer.cert_pem()]);
    assert_eq!(results.len(), 1, "exactly one signature");
    assert!(results[0].all_reference_digests_verified());
    match &results[0] {
        VerifyResult::Valid { references, .. } => {
            assert_eq!(references.len(), 1);
            assert_eq!(references[0].uri, "#_a1");
            assert!(references[0].digest_verified);
            assert_eq!(
                references[0].resolved_node,
                Some(assertion),
                "reference resolves to the Assertion"
            );
        }
        VerifyResult::Invalid { reason } => panic!("expected a valid signature, got: {reason}"),
    }
}

#[test]
fn spike_rsa_sha256_assertion_signs_and_verifies() {
    assert_assertion_verified(Alg::Rsa);
}

#[test]
fn spike_ecdsa_p256_assertion_signs_and_verifies() {
    assert_assertion_verified(Alg::Ecdsa);
}

#[test]
fn spike_tampered_value_fails() {
    let signer = generate(Alg::Rsa, "Spike IdP");
    let signed = sign_response(Alg::Rsa, &signer);
    let original = "<saml:NameID>alice@example.test</saml:NameID>";
    assert!(signed.contains(original));
    // One character inside the signed assertion.
    let tampered = signed.replace(original, "<saml:NameID>alicf@example.test</saml:NameID>");
    assert_ne!(tampered, signed);
    let (results, _) = verify(&tampered, &[signer.cert_pem()]);
    assert_eq!(results.len(), 1);
    assert!(!results[0].is_valid(), "tampered assertion must not verify");
}

#[test]
fn spike_untrusted_key_in_keyinfo_fails() {
    let trusted = generate(Alg::Rsa, "Configured IdP");
    let attacker = generate(Alg::Rsa, "Attacker");
    // The attacker signs and embeds its own certificate in KeyInfo/X509Data.
    let signed = sign_response(Alg::Rsa, &attacker);
    let attacker_cert_b64 = b64std(&attacker.cert_der);
    assert!(signed.contains("X509Certificate"));
    assert!(signed.contains(&attacker_cert_b64[..48]));
    let (results, _) = verify(&signed, &[trusted.cert_pem()]);
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].is_valid(),
        "a key from KeyInfo must never be trusted"
    );
    // Control: the same document verifies when the attacker's cert is the configured one.
    let (control, _) = verify(&signed, &[attacker.cert_pem()]);
    assert!(control[0].is_valid());
}
