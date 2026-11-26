//! Test-only SAML IdP (06-09, shared with 06-18): keys and self-signed certificates generated at
//! test time with aws-lc-rs, a `samlp:Response` builder, a signer on bergshamra-dsig's
//! template-based `sign::sign`, and string mutators for the attack corpus.
//!
//! Nothing secret is committed: every key exists only in memory for one test run, and the PKCS#8
//! PEM label is assembled at runtime.
//!
//! - [`IdpKey::rsa`] / [`IdpKey::ecdsa`]: an RSA-2048 or P-256 signer, [`IdpKey::cert_pem`] is
//!   what an operator would paste into the connection.
//! - [`ResponseOpts::valid`]: a response that passes core's `saml::validate::check` at `now` for
//!   [`SP_ENTITY_ID`] / [`ACS_URL`] / [`REQUEST_ID`] / [`IDP_ENTITY_ID`].
//! - [`signed_response`]: build and sign (Assertion and/or Response, per the options).
//! - [`assertion_xml`], [`response_xml`], [`signature_template`], [`sign_first`]: the pieces, for
//!   corpus cases that need a custom structure.
//! - [`replace_once`], [`element`], [`remove`], [`insert_after`], [`insert_before`]: mutators.

#![allow(dead_code)]

use anvil_core::saml::saml_instant;
use anvil_jose::encoding::b64std;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PKCS1_SHA256,
};
use bergshamra_dsig::DsigContext;
use bergshamra_keys::{Key, KeysManager, loader};
use time::{Duration, OffsetDateTime};

pub const SP_ENTITY_ID: &str = "https://sp.example.test/saml/metadata";
pub const ACS_URL: &str = "https://sp.example.test/saml/acs";
pub const IDP_ENTITY_ID: &str = "https://idp.example.test/entity";
pub const REQUEST_ID: &str = "_0123456789abcdef0123456789abcdef";
pub const RESPONSE_ID: &str = "_resp1";
pub const ASSERTION_ID: &str = "_assert1";
pub const NAME_ID: &str = "alice@example.test";

pub const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
pub const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
pub const FORMAT_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
pub const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
pub const HMAC_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
pub const DIGEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const DIGEST_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
pub const C14N_10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const XPATH: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
pub const XSLT: &str = "http://www.w3.org/TR/1999/REC-xslt-19991116";

// ---------------------------------------------------------------------------------------------
// Keys and certificates.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Rsa,
    Ecdsa,
}

impl Alg {
    pub fn signature_method(self) -> &'static str {
        match self {
            Alg::Rsa => RSA_SHA256,
            Alg::Ecdsa => ECDSA_SHA256,
        }
    }
}

/// A generated IdP signer: PKCS#8 private key (DER, memory only) and its self-signed cert.
pub struct IdpKey {
    pub alg: Alg,
    pkcs8: Vec<u8>,
    pub cert_der: Vec<u8>,
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

/// A minimal self-signed X.509 v3 certificate (validity 2025-2049; the adapter ignores it).
fn self_signed_cert(
    alg: Alg,
    common_name: &str,
    spki: &[u8],
    sign: impl Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let sig_alg = match alg {
        Alg::Rsa => seq(&[&oid(&[1, 2, 840, 113549, 1, 1, 11]), &[0x05, 0x00]]),
        Alg::Ecdsa => seq(&[&oid(&[1, 2, 840, 10045, 4, 3, 2])]),
    };
    let subject = name(common_name);
    let validity = seq(&[&tlv(0x17, b"250101000000Z"), &tlv(0x17, b"491231235959Z")]);
    let tbs = seq(&[
        &tlv(0xa0, &tlv(0x02, &[0x02])),
        &tlv(0x02, &[0x01, 0x23, 0x45]),
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

/// PEM armour in memory (64-column lines).
pub fn pem(label: &str, der: &[u8]) -> String {
    let b64 = b64std(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

impl IdpKey {
    pub fn generate(alg: Alg, common_name: &str) -> Self {
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
                Self {
                    alg,
                    pkcs8: pkcs8.as_ref().to_vec(),
                    cert_der,
                }
            }
            Alg::Ecdsa => {
                let kp =
                    EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("ec keygen");
                let pkcs8 = kp.to_pkcs8v1().expect("pkcs8");
                let spki = kp.public_key().as_der().expect("spki");
                let cert_der = self_signed_cert(alg, common_name, spki.as_ref(), |tbs| {
                    kp.sign(&rng, tbs).expect("ec sign").as_ref().to_vec()
                });
                Self {
                    alg,
                    pkcs8: pkcs8.as_ref().to_vec(),
                    cert_der,
                }
            }
        }
    }

    pub fn rsa() -> Self {
        Self::generate(Alg::Rsa, "Test IdP")
    }

    pub fn ecdsa() -> Self {
        Self::generate(Alg::Ecdsa, "Test IdP")
    }

    /// The signing certificate as an operator pastes it into the connection.
    pub fn cert_pem(&self) -> String {
        pem("CERTIFICATE", &self.cert_der)
    }

    /// The certificate as one base64 string (an `X509Certificate` value).
    pub fn cert_b64(&self) -> String {
        b64std(&self.cert_der)
    }

    /// The bergshamra signing key, carrying its certificate so `<ds:X509Data/>` gets filled.
    pub fn signing_key(&self) -> Key {
        let label = ["PRIVATE", "KEY"].join(" ");
        let pem = pem(&label, &self.pkcs8);
        let mut key = match self.alg {
            Alg::Rsa => loader::load_rsa_private_pem(pem.as_bytes()),
            Alg::Ecdsa => loader::load_ec_p256_private_pem(pem.as_bytes()),
        }
        .expect("load generated private key");
        key.x509_chain = vec![self.cert_der.clone()];
        key
    }
}

// ---------------------------------------------------------------------------------------------
// Response builder.
// ---------------------------------------------------------------------------------------------

/// `SubjectConfirmation` values.
#[derive(Clone, Debug)]
pub struct Confirmation {
    pub method: String,
    pub recipient: Option<String>,
    pub in_response_to: Option<String>,
    pub not_on_or_after: Option<OffsetDateTime>,
}

/// `Conditions` values.
#[derive(Clone, Debug)]
pub struct Conditions {
    pub not_before: Option<OffsetDateTime>,
    pub not_on_or_after: Option<OffsetDateTime>,
    /// One inner list per `AudienceRestriction`.
    pub audiences: Vec<Vec<String>>,
}

/// Everything the builder writes. `None` omits the attribute or element.
#[derive(Clone, Debug)]
pub struct ResponseOpts {
    pub response_id: String,
    pub assertion_id: String,
    pub destination: Option<String>,
    pub in_response_to: Option<String>,
    pub response_issuer: Option<String>,
    pub issuer: String,
    pub status_code: String,
    pub issue_instant: OffsetDateTime,
    pub name_id: String,
    pub name_id_format: Option<String>,
    pub confirmation: Option<Confirmation>,
    pub conditions: Option<Conditions>,
    pub authn_statement: bool,
    pub session_index: Option<String>,
    /// `(Name, FriendlyName, values)`.
    pub attributes: Vec<(String, Option<String>, Vec<String>)>,
    pub sign_assertion: bool,
    pub sign_response: bool,
}

impl ResponseOpts {
    /// A response core accepts at `now`: Assertion signed, Response unsigned.
    pub fn valid(now: OffsetDateTime) -> Self {
        Self {
            response_id: RESPONSE_ID.into(),
            assertion_id: ASSERTION_ID.into(),
            destination: Some(ACS_URL.into()),
            in_response_to: Some(REQUEST_ID.into()),
            response_issuer: Some(IDP_ENTITY_ID.into()),
            issuer: IDP_ENTITY_ID.into(),
            status_code: STATUS_SUCCESS.into(),
            issue_instant: now,
            name_id: NAME_ID.into(),
            name_id_format: Some(FORMAT_EMAIL.into()),
            confirmation: Some(Confirmation {
                method: CM_BEARER.into(),
                recipient: Some(ACS_URL.into()),
                in_response_to: Some(REQUEST_ID.into()),
                not_on_or_after: Some(now + Duration::minutes(5)),
            }),
            conditions: Some(Conditions {
                not_before: Some(now - Duration::seconds(30)),
                not_on_or_after: Some(now + Duration::minutes(5)),
                audiences: vec![vec![SP_ENTITY_ID.into()]],
            }),
            authn_statement: true,
            session_index: Some("_session1".into()),
            attributes: vec![
                (
                    "urn:oid:0.9.2342.19200300.100.1.3".into(),
                    Some("mail".into()),
                    vec![NAME_ID.into()],
                ),
                ("givenName".into(), None, vec!["Alice".into()]),
            ],
            sign_assertion: true,
            sign_response: false,
        }
    }
}

impl Default for ResponseOpts {
    fn default() -> Self {
        Self::valid(OffsetDateTime::now_utc())
    }
}

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn opt_attr(name: &str, value: Option<&str>) -> String {
    value
        .map(|v| format!(" {name}=\"{}\"", esc(v)))
        .unwrap_or_default()
}

/// An unsigned enveloped signature template (exc-c14n, `alg`, SHA-256, `Reference URI="#id"`).
pub fn signature_template(alg: Alg, reference_id: &str) -> String {
    format!(
        "<ds:Signature xmlns:ds=\"{NS_DSIG}\"><ds:SignedInfo>\
<ds:CanonicalizationMethod Algorithm=\"{EXC_C14N}\"/>\
<ds:SignatureMethod Algorithm=\"{sm}\"/>\
<ds:Reference URI=\"#{id}\"><ds:Transforms>\
<ds:Transform Algorithm=\"{ENVELOPED}\"/><ds:Transform Algorithm=\"{EXC_C14N}\"/>\
</ds:Transforms><ds:DigestMethod Algorithm=\"{DIGEST_SHA256}\"/>\
<ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo>\
<ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data/></ds:KeyInfo></ds:Signature>",
        sm = alg.signature_method(),
        id = esc(reference_id),
    )
}

/// The `saml:Assertion` element (standalone: declares its own `saml` namespace). With
/// `signature = Some(alg)` it carries an empty signature template right after the Issuer.
pub fn assertion_xml(o: &ResponseOpts, signature: Option<Alg>) -> String {
    let mut x = format!(
        "<saml:Assertion xmlns:saml=\"{NS_ASSERTION}\" ID=\"{}\" Version=\"2.0\" IssueInstant=\"{}\">\
<saml:Issuer>{}</saml:Issuer>",
        esc(&o.assertion_id),
        saml_instant(o.issue_instant),
        esc(&o.issuer)
    );
    if let Some(alg) = signature {
        x.push_str(&signature_template(alg, &o.assertion_id));
    }
    x.push_str(&format!(
        "<saml:Subject><saml:NameID{}>{}</saml:NameID>",
        opt_attr("Format", o.name_id_format.as_deref()),
        esc(&o.name_id)
    ));
    if let Some(c) = &o.confirmation {
        x.push_str(&format!(
            "<saml:SubjectConfirmation Method=\"{}\"><saml:SubjectConfirmationData{}{}{}/></saml:SubjectConfirmation>",
            esc(&c.method),
            opt_attr("NotOnOrAfter", c.not_on_or_after.map(saml_instant).as_deref()),
            opt_attr("Recipient", c.recipient.as_deref()),
            opt_attr("InResponseTo", c.in_response_to.as_deref()),
        ));
    }
    x.push_str("</saml:Subject>");
    if let Some(c) = &o.conditions {
        x.push_str(&format!(
            "<saml:Conditions{}{}>",
            opt_attr("NotBefore", c.not_before.map(saml_instant).as_deref()),
            opt_attr(
                "NotOnOrAfter",
                c.not_on_or_after.map(saml_instant).as_deref()
            ),
        ));
        for restriction in &c.audiences {
            x.push_str("<saml:AudienceRestriction>");
            for a in restriction {
                x.push_str(&format!("<saml:Audience>{}</saml:Audience>", esc(a)));
            }
            x.push_str("</saml:AudienceRestriction>");
        }
        x.push_str("</saml:Conditions>");
    }
    if o.authn_statement {
        x.push_str(&format!(
            "<saml:AuthnStatement AuthnInstant=\"{}\"{}><saml:AuthnContext>\
<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\
</saml:AuthnContext></saml:AuthnStatement>",
            saml_instant(o.issue_instant),
            opt_attr("SessionIndex", o.session_index.as_deref()),
        ));
    }
    if !o.attributes.is_empty() {
        x.push_str("<saml:AttributeStatement>");
        for (name, friendly, values) in &o.attributes {
            x.push_str(&format!(
                "<saml:Attribute Name=\"{}\"{}>",
                esc(name),
                opt_attr("FriendlyName", friendly.as_deref())
            ));
            for v in values {
                x.push_str(&format!(
                    "<saml:AttributeValue>{}</saml:AttributeValue>",
                    esc(v)
                ));
            }
            x.push_str("</saml:Attribute>");
        }
        x.push_str("</saml:AttributeStatement>");
    }
    x.push_str("</saml:Assertion>");
    x
}

/// The `samlp:Response` around `assertion` (inserted verbatim). With `signature = Some(alg)` it
/// carries an empty Response signature template right after the Issuer.
pub fn response_xml(o: &ResponseOpts, signature: Option<Alg>, assertion: &str) -> String {
    let mut x = format!(
        "<samlp:Response xmlns:samlp=\"{NS_PROTOCOL}\" xmlns:saml=\"{NS_ASSERTION}\" ID=\"{}\" \
Version=\"2.0\" IssueInstant=\"{}\"{}{}>",
        esc(&o.response_id),
        saml_instant(o.issue_instant),
        opt_attr("Destination", o.destination.as_deref()),
        opt_attr("InResponseTo", o.in_response_to.as_deref()),
    );
    if let Some(issuer) = &o.response_issuer {
        x.push_str(&format!("<saml:Issuer>{}</saml:Issuer>", esc(issuer)));
    }
    if let Some(alg) = signature {
        x.push_str(&signature_template(alg, &o.response_id));
    }
    x.push_str(&format!(
        "<samlp:Status><samlp:StatusCode Value=\"{}\"/></samlp:Status>",
        esc(&o.status_code)
    ));
    x.push_str(assertion);
    x.push_str("</samlp:Response>");
    x
}

/// Signs the first `ds:Signature` template in document order with `key` (bergshamra's
/// template-based `sign::sign`).
pub fn sign_first(key: &IdpKey, template: &str) -> String {
    let mut keys = KeysManager::new();
    keys.add_key(key.signing_key());
    let ctx = DsigContext::new(keys);
    let signed = bergshamra_dsig::sign::sign(&ctx, template).expect("sign template");
    match signed.strip_prefix("<?xml") {
        Some(rest) => rest[rest.find("?>").expect("decl end") + 2..]
            .trim_start()
            .to_owned(),
        None => signed,
    }
}

/// The signed Assertion element alone (standalone, signed by `key`).
pub fn signed_assertion(key: &IdpKey, o: &ResponseOpts) -> String {
    sign_first(key, &assertion_xml(o, Some(key.alg)))
}

/// Builds and signs a response: the Assertion first (when `sign_assertion`), then the Response
/// around it (when `sign_response`).
pub fn signed_response(key: &IdpKey, o: &ResponseOpts) -> String {
    let assertion = if o.sign_assertion {
        signed_assertion(key, o)
    } else {
        assertion_xml(o, None)
    };
    let response = response_xml(o, o.sign_response.then_some(key.alg), &assertion);
    if o.sign_response {
        sign_first(key, &response)
    } else {
        response
    }
}

// ---------------------------------------------------------------------------------------------
// Mutators (plain string edits on generated XML).
// ---------------------------------------------------------------------------------------------

/// Replaces the single occurrence of `from` (panics unless it occurs exactly once).
pub fn replace_once(xml: &str, from: &str, to: &str) -> String {
    assert_eq!(
        xml.matches(from).count(),
        1,
        "expected exactly one {from:?} in the document"
    );
    xml.replacen(from, to, 1)
}

/// The first element that starts with `open` (for example `"<saml:Assertion"`) up to and
/// including the first `close` after it (for example `"</saml:Assertion>"`).
pub fn element<'a>(xml: &'a str, open: &str, close: &str) -> &'a str {
    let start = xml.find(open).unwrap_or_else(|| panic!("no {open:?}"));
    let end = xml[start..]
        .find(close)
        .unwrap_or_else(|| panic!("no {close:?} after {open:?}"))
        + start
        + close.len();
    &xml[start..end]
}

/// Removes the single occurrence of `part`.
pub fn remove(xml: &str, part: &str) -> String {
    replace_once(xml, part, "")
}

/// Inserts `addition` right after the single occurrence of `anchor`.
pub fn insert_after(xml: &str, anchor: &str, addition: &str) -> String {
    replace_once(xml, anchor, &format!("{anchor}{addition}"))
}

/// Inserts `addition` right before the single occurrence of `anchor`.
pub fn insert_before(xml: &str, anchor: &str, addition: &str) -> String {
    replace_once(xml, anchor, &format!("{addition}{anchor}"))
}

/// The Assertion's signature element in a signed document.
pub fn assertion_signature(xml: &str) -> &str {
    let assertion = element(xml, "<saml:Assertion", "</saml:Assertion>");
    element(assertion, "<ds:Signature", "</ds:Signature>")
}
