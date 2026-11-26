//! SAML XML handling (`ports::SamlXml`, ORG-03, decision D4): one strict parser, a profile
//! pre-check, XML-DSig verification against the configured certificates only, and extraction from
//! the verified node only.
//!
//! The order is fixed, and each step is a refusal point:
//!
//! 1. **Size and markup caps** on the raw bytes (256 KiB, at most [`MAX_MARKUP`] `<` bytes, which
//!    bounds the node count before anything is allocated), UTF-8 only.
//! 2. **One parse** by uppsala with `with_forbid_dtd(true)` (DTDs are parsed by default in uppsala,
//!    so the flag is mandatory) and a nesting cap of 64. No processing instructions, an absolute
//!    URI for every namespace declaration (relative namespace URIs are the "void canonicalization"
//!    class), no attribute local name twice on one element (attribute pollution such as
//!    `ID` + `samlp:ID`), no duplicate id value anywhere.
//! 3. **Profile pre-check** ([`precheck`]) before any bergshamra call: root
//!    `{protocol}Response` with `Version="2.0"`, a fixed child sequence, exactly one
//!    `{assertion}Assertion` in the whole document (a Response child), no encrypted element, the
//!    Assertion signature pinned as the direct child after its Issuer, at most one Response
//!    signature (after the Response Issuer), no other `ds:Signature` anywhere, exactly one
//!    `Reference` per signature whose URI is `#` + the signed element's `ID`, transforms exactly
//!    `[enveloped-signature, exc-c14n]`, exc-c14n without comments, allow-listed signature and
//!    digest algorithms. bergshamra resolves non-fragment Reference URIs as files relative to the
//!    process working directory; the pre-check refuses them first, so that code is never reached.
//! 4. **Verification** with bergshamra-dsig on aws-lc: keys come only from `signing_certs` (never
//!    `KeyInfo`), strict mode, every reference digest verified, X.509 time and chain checks
//!    skipped (pinned keys; assertion times are judged in core on the injected clock). Results
//!    are mapped to the pinned signatures by position, and the verified reference must resolve to
//!    the pre-checked node. A present Response signature must verify too.
//! 5. **Extraction** ([`extract`]) reads the assertion values only from the verified Assertion
//!    node, in the same `Document` (no second parser, no re-parse), plus the Response's own
//!    attributes, Issuer and Status. NameID, Issuer, Audience and attribute values must be text
//!    only: a comment, processing instruction or child element inside them is refused (the
//!    comment-injection class). Values are trimmed of XML whitespace.
//!
//! This adapter does not judge Destination, InResponseTo, Status, audiences or times: core's
//! `saml::validate::check` does, on the extracted values.
//!
//! IdP metadata ([`SamlXmlAdapter::parse_metadata`]) goes through the same parser and caps. Its
//! signature is **not** verified: metadata is pasted by an operator or imported from an https URL
//! the operator chose, and the operator confirms the certificates before saving.

use std::collections::{BTreeMap, HashSet};
use std::io::Write as _;
use std::sync::Arc;

use anvil_core::model::{IdpMetadata, SamlAssertionData, SamlSubjectConfirmation};
use anvil_core::ports::{SamlXml, SamlXmlReject};
use anvil_core::saml::{NS_ASSERTION, NS_METADATA, NS_PROTOCOL};
use anvil_jose::encoding::{b64std, b64std_decode};
use bergshamra_dsig::{DsigContext, VerifiedReference, VerifyResult};
use bergshamra_keys::{KeysManager, loader};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uppsala::{Document, NodeId, NodeKind};

use crate::state::AppState;

type R = SamlXmlReject;

/// Largest decoded `SAMLResponse`, in bytes.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// Largest IdP metadata document, in bytes.
pub const MAX_METADATA_BYTES: usize = 1024 * 1024;
/// Largest AuthnRequest accepted by [`SamlXmlAdapter::encode_redirect`], in bytes.
pub const MAX_AUTHN_REQUEST_BYTES: usize = 64 * 1024;
/// Deepest element nesting the parser accepts.
pub const MAX_DEPTH: u32 = 64;
/// Most `<` bytes in a response (an upper bound on elements, comments and processing
/// instructions, so on the node count), checked before parsing.
pub const MAX_MARKUP: usize = 16 * 1024;
/// Most `<` bytes in a metadata document.
pub const MAX_METADATA_MARKUP: usize = 64 * 1024;

const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const NS_XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const NS_XENC11: &str = "http://www.w3.org/2009/xmlenc11#";
const BINDING_HTTP_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

/// Exclusive canonicalisation without comments (the only allowed c14n, and the namespace of
/// `InclusiveNamespaces`).
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// The enveloped-signature transform.
pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// Allowed `SignatureMethod` algorithms (no SHA-1, no HMAC).
pub const SIGNATURE_METHODS: &[&str] = &[
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
];

/// Allowed `DigestMethod` algorithms (no SHA-1).
pub const DIGEST_METHODS: &[&str] = &[
    "http://www.w3.org/2001/04/xmlenc#sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512",
];

/// Attribute local names bergshamra registers as element ids (plus `xml:id`, local name `id`).
/// Every one of them takes part in the duplicate-id check, whatever its namespace.
const ID_ATTRS: &[&str] = &["ID", "Id", "id", "AssertionID"];

/// The production [`SamlXml`] (module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct SamlXmlAdapter;

impl SamlXml for SamlXmlAdapter {
    fn verify_response(
        &self,
        xml: &[u8],
        signing_certs: &[String],
    ) -> Result<SamlAssertionData, SamlXmlReject> {
        let text = checked_text(xml, MAX_RESPONSE_BYTES, MAX_MARKUP)?;
        let doc = parse(text)?;
        document_rules(&doc)?;
        let pre = precheck(&doc)?;
        verify(&doc, text, &pre, signing_certs)?;
        extract(&doc, pre.assertion)
    }

    fn parse_metadata(&self, xml: &[u8]) -> Result<IdpMetadata, SamlXmlReject> {
        let text = checked_text(xml, MAX_METADATA_BYTES, MAX_METADATA_MARKUP)?;
        let doc = parse(text)?;
        document_rules(&doc)?;
        metadata(&doc)
    }

    fn encode_redirect(&self, authn_request_xml: &str) -> Result<String, SamlXmlReject> {
        if authn_request_xml.len() > MAX_AUTHN_REQUEST_BYTES {
            return Err(R::Size);
        }
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(authn_request_xml.as_bytes())
            .map_err(|_| R::Unavailable)?;
        let raw = encoder.finish().map_err(|_| R::Unavailable)?;
        Ok(b64std(&raw))
    }
}

impl AppState {
    /// The SAML XML adapter services use (stateless).
    pub(crate) fn saml_xml(&self) -> Arc<dyn SamlXml> {
        Arc::new(SamlXmlAdapter)
    }
}

// ---------------------------------------------------------------------------------------------
// Step 1-2: caps, the one parser, document-wide rules.
// ---------------------------------------------------------------------------------------------

/// Size cap, markup cap and UTF-8, before the parser sees a byte. Borrows the caller's bytes.
fn checked_text(xml: &[u8], max_bytes: usize, max_markup: usize) -> Result<&str, R> {
    if xml.len() > max_bytes {
        return Err(R::Size);
    }
    if xml.iter().filter(|b| **b == b'<').count() > max_markup {
        return Err(R::Size);
    }
    let text = std::str::from_utf8(xml).map_err(|_| R::Parse)?;
    Ok(text.strip_prefix('\u{feff}').unwrap_or(text))
}

/// The one parser: uppsala, DTDs forbidden, nesting capped. A DOCTYPE or entity declaration
/// anywhere is [`R::Dtd`]; any other parse failure (including the depth cap) is [`R::Parse`].
fn parse(text: &str) -> Result<Document<'_>, R> {
    let parsed = uppsala::Parser::new()
        .with_forbid_dtd(true)
        .with_forbid_entities(true)
        .with_max_depth(MAX_DEPTH)
        .parse(text);
    match parsed {
        Ok(doc) if doc.doctype.is_some() => Err(R::Dtd),
        Ok(doc) if doc.document_element().is_none() => Err(R::Parse),
        Ok(doc) => {
            if let Some(decl) = &doc.xml_declaration
                && let Some(enc) = &decl.encoding
                && !enc.eq_ignore_ascii_case("UTF-8")
            {
                return Err(R::Parse);
            }
            Ok(doc)
        }
        Err(_) if text.contains("<!DOCTYPE") || text.contains("<!ENTITY") => Err(R::Dtd),
        Err(_) => Err(R::Parse),
    }
}

/// Whether `uri` has a URI scheme (`scheme ":" ...`), i.e. is not a relative reference.
fn is_absolute_uri(uri: &str) -> bool {
    let Some((scheme, _)) = uri.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn is_encrypted_element(ns: Option<&str>, local: &str) -> bool {
    match ns {
        Some(NS_XENC) | Some(NS_XENC11) => true,
        Some(NS_ASSERTION) => matches!(
            local,
            "EncryptedAssertion" | "EncryptedID" | "EncryptedAttribute"
        ),
        Some(NS_PROTOCOL) => local == "NewEncryptedID",
        _ => false,
    }
}

/// Document-wide rules, each in its own pass so the reason does not depend on element order:
/// processing instructions and relative namespace URIs ([`R::Structure`]), encrypted elements
/// ([`R::Encrypted`]), an attribute local name twice on one element ([`R::Structure`]), and a
/// duplicate id value anywhere ([`R::DuplicateId`]).
fn document_rules(doc: &Document<'_>) -> Result<(), R> {
    let nodes = doc.descendants(doc.root());
    let elements = || {
        nodes
            .iter()
            .filter_map(|id| doc.element(*id).map(|e| (*id, e)))
    };

    for id in &nodes {
        if matches!(doc.node_kind(*id), Some(NodeKind::ProcessingInstruction(_))) {
            return Err(R::Structure);
        }
    }
    for (_, e) in elements() {
        if e.namespace_declarations
            .iter()
            .any(|(_, uri)| !uri.is_empty() && !is_absolute_uri(uri))
        {
            return Err(R::Structure);
        }
    }
    for (_, e) in elements() {
        if is_encrypted_element(e.name.namespace_uri.as_deref(), &e.name.local_name) {
            return Err(R::Encrypted);
        }
    }
    for (_, e) in elements() {
        let mut seen = HashSet::new();
        if !e
            .attributes
            .iter()
            .all(|a| seen.insert(a.name.local_name.as_ref()))
        {
            return Err(R::Structure);
        }
    }
    let mut ids = HashSet::new();
    for (_, e) in elements() {
        for a in &e.attributes {
            if ID_ATTRS.contains(&a.name.local_name.as_ref()) && !ids.insert(a.value.as_ref()) {
                return Err(R::DuplicateId);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// DOM helpers (namespace URIs, never prefixes).
// ---------------------------------------------------------------------------------------------

fn is_el(doc: &Document<'_>, id: NodeId, ns: &str, local: &str) -> bool {
    doc.element(id)
        .is_some_and(|e| e.name.namespace_uri.as_deref() == Some(ns) && e.name.local_name == local)
}

fn child_elements(doc: &Document<'_>, id: NodeId) -> Vec<NodeId> {
    doc.children_iter(id)
        .filter(|c| doc.element(*c).is_some())
        .collect()
}

fn children_named(doc: &Document<'_>, id: NodeId, ns: &str, local: &str) -> Vec<NodeId> {
    doc.children_iter(id)
        .filter(|c| is_el(doc, *c, ns, local))
        .collect()
}

fn first_child_named(doc: &Document<'_>, id: NodeId, ns: &str, local: &str) -> Option<NodeId> {
    doc.children_iter(id).find(|c| is_el(doc, *c, ns, local))
}

/// An unqualified attribute (no namespace). A prefixed attribute with the same local name never
/// matches (and cannot coexist with it: [`document_rules`]).
fn attr<'d>(doc: &'d Document<'_>, id: NodeId, name: &str) -> Option<&'d str> {
    doc.element(id)?
        .attributes
        .iter()
        .find(|a| {
            a.name.namespace_uri.is_none() && a.name.prefix.is_none() && a.name.local_name == name
        })
        .map(|a| a.value.as_ref())
}

/// The text of an element made of text and CDATA only, trimmed. A comment, processing
/// instruction or child element inside it is refused ([`R::Structure`]): readers that take the
/// first text node would see a different value than the canonical form that was signed.
fn text_only(doc: &Document<'_>, id: NodeId) -> Result<String, R> {
    let mut out = String::new();
    for child in doc.children_iter(id) {
        match doc.node_kind(child) {
            Some(NodeKind::Text(t)) | Some(NodeKind::CData(t)) => out.push_str(t),
            _ => return Err(R::Structure),
        }
    }
    Ok(out
        .trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
        .to_owned())
}

fn instant(value: &str) -> Result<OffsetDateTime, R> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| R::Structure)
}

fn opt_instant(value: Option<&str>) -> Result<Option<OffsetDateTime>, R> {
    value.map(instant).transpose()
}

// ---------------------------------------------------------------------------------------------
// Step 3: the profile pre-check.
// ---------------------------------------------------------------------------------------------

/// What the pre-check pinned: the Assertion, its signature, the optional Response signature, and
/// their positions among all `ds:Signature` elements in document order (bergshamra's result
/// order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prechecked {
    pub assertion: NodeId,
    pub assertion_signature: NodeId,
    pub assertion_signature_index: usize,
    pub response_signature: Option<NodeId>,
    pub response_signature_index: Option<usize>,
    pub signature_count: usize,
}

/// The strict SAML profile check (module docs, step 3). Runs before any bergshamra call and
/// touches nothing outside `doc`. Expects [`document_rules`] to have passed.
pub fn precheck(doc: &Document<'_>) -> Result<Prechecked, R> {
    let root = doc.document_element().ok_or(R::Structure)?;
    if !is_el(doc, root, NS_PROTOCOL, "Response") || attr(doc, root, "Version") != Some("2.0") {
        return Err(R::Structure);
    }

    // Response children: Issuer? Signature? Extensions? Status Assertion (signatures are
    // checked below with their own reason).
    let mut stage = 0u8;
    let mut assertion = None;
    let mut response_issuer = None;
    for c in child_elements(doc, root) {
        if is_el(doc, c, NS_DSIG, "Signature") {
            continue;
        }
        let rank = if is_el(doc, c, NS_ASSERTION, "Issuer") {
            response_issuer = Some(c);
            1
        } else if is_el(doc, c, NS_PROTOCOL, "Extensions") {
            2
        } else if is_el(doc, c, NS_PROTOCOL, "Status") {
            3
        } else if is_el(doc, c, NS_ASSERTION, "Assertion") {
            assertion = Some(c);
            4
        } else {
            return Err(R::Structure);
        };
        if rank <= stage {
            return Err(R::Structure);
        }
        stage = rank;
    }
    let assertion = assertion.ok_or(R::Structure)?;
    if stage != 4 || first_child_named(doc, root, NS_PROTOCOL, "Status").is_none() {
        return Err(R::Structure);
    }

    // Exactly one Assertion in the whole document (none in Extensions, Advice, Object, ...).
    let all = doc.descendants(doc.root());
    let assertion_count = all
        .iter()
        .filter(|n| is_el(doc, **n, NS_ASSERTION, "Assertion"))
        .count();
    if assertion_count != 1 {
        return Err(R::Structure);
    }

    // Assertion children: Issuer first, then Subject? Conditions? statements (no Advice).
    let assertion_children = child_elements(doc, assertion);
    let mut stage = 0u8;
    let mut assertion_issuer = None;
    for c in &assertion_children {
        let c = *c;
        if is_el(doc, c, NS_DSIG, "Signature") {
            continue;
        }
        let rank = if is_el(doc, c, NS_ASSERTION, "Issuer") {
            assertion_issuer = Some(c);
            1
        } else if is_el(doc, c, NS_ASSERTION, "Subject") {
            2
        } else if is_el(doc, c, NS_ASSERTION, "Conditions") {
            3
        } else if is_el(doc, c, NS_ASSERTION, "AuthnStatement")
            || is_el(doc, c, NS_ASSERTION, "AttributeStatement")
            || is_el(doc, c, NS_ASSERTION, "AuthzDecisionStatement")
        {
            4
        } else {
            return Err(R::Structure);
        };
        if rank < stage || (rank == stage && rank < 4) {
            return Err(R::Structure);
        }
        stage = rank;
    }
    let assertion_issuer = assertion_issuer.ok_or(R::Structure)?;
    if assertion_children.first() != Some(&assertion_issuer) {
        return Err(R::Structure);
    }

    // Signatures: the Assertion's is pinned right after its Issuer; the Response's (optional)
    // right after the Response Issuer (or first); no other ds:Signature anywhere.
    let signatures: Vec<NodeId> = all
        .iter()
        .copied()
        .filter(|n| is_el(doc, *n, NS_DSIG, "Signature"))
        .collect();
    let assertion_sigs = children_named(doc, assertion, NS_DSIG, "Signature");
    let [assertion_signature] = assertion_sigs[..] else {
        return Err(R::SignatureProfile);
    };
    if assertion_children.get(1) != Some(&assertion_signature) {
        return Err(R::SignatureProfile);
    }
    let response_sigs = children_named(doc, root, NS_DSIG, "Signature");
    if response_sigs.len() > 1 || signatures.len() != 1 + response_sigs.len() {
        return Err(R::SignatureProfile);
    }
    let response_signature = response_sigs.first().copied();
    if let Some(sig) = response_signature {
        let root_children = child_elements(doc, root);
        let expected_pos = usize::from(response_issuer.is_some());
        if root_children.get(expected_pos) != Some(&sig) {
            return Err(R::SignatureProfile);
        }
    }

    let assertion_id = attr(doc, assertion, "ID").ok_or(R::Structure)?;
    if assertion_id.is_empty() {
        return Err(R::Structure);
    }
    signature_profile(doc, assertion_signature, assertion_id)?;
    if let Some(sig) = response_signature {
        let response_id = attr(doc, root, "ID")
            .filter(|id| !id.is_empty())
            .ok_or(R::SignatureProfile)?;
        signature_profile(doc, sig, response_id)?;
    }

    let index_of = |n: NodeId| signatures.iter().position(|s| *s == n);
    Ok(Prechecked {
        assertion,
        assertion_signature,
        assertion_signature_index: index_of(assertion_signature).ok_or(R::SignatureProfile)?,
        response_signature,
        response_signature_index: response_signature.and_then(index_of),
        signature_count: signatures.len(),
    })
}

/// At most one `ec:InclusiveNamespaces` child, nothing else.
fn only_inclusive_namespaces(doc: &Document<'_>, id: NodeId) -> Result<(), R> {
    let children = child_elements(doc, id);
    if children.len() > 1
        || children
            .iter()
            .any(|c| !is_el(doc, *c, EXC_C14N, "InclusiveNamespaces"))
    {
        return Err(R::SignatureProfile);
    }
    Ok(())
}

fn algorithm<'d>(doc: &'d Document<'_>, id: NodeId) -> Result<&'d str, R> {
    attr(doc, id, "Algorithm").ok_or(R::SignatureProfile)
}

/// One signature against the profile: `SignedInfo`, `SignatureValue`, optional `KeyInfo` (no
/// `Object`); exc-c14n; an allowed signature method; one Reference to `#target_id` with the
/// transforms `[enveloped, exc-c14n]` and an allowed digest; non-empty values. A disallowed
/// algorithm is [`R::Algorithm`]; every other deviation is [`R::SignatureProfile`].
fn signature_profile(doc: &Document<'_>, sig: NodeId, target_id: &str) -> Result<(), R> {
    let children = child_elements(doc, sig);
    let (signed_info, signature_value, key_info) = match children[..] {
        [si, sv]
            if is_el(doc, si, NS_DSIG, "SignedInfo")
                && is_el(doc, sv, NS_DSIG, "SignatureValue") =>
        {
            (si, sv, None)
        }
        [si, sv, ki]
            if is_el(doc, si, NS_DSIG, "SignedInfo")
                && is_el(doc, sv, NS_DSIG, "SignatureValue")
                && is_el(doc, ki, NS_DSIG, "KeyInfo") =>
        {
            (si, sv, Some(ki))
        }
        _ => return Err(R::SignatureProfile),
    };

    let si_children = child_elements(doc, signed_info);
    let [c14n, method, references @ ..] = &si_children[..] else {
        return Err(R::SignatureProfile);
    };
    if !is_el(doc, *c14n, NS_DSIG, "CanonicalizationMethod")
        || !is_el(doc, *method, NS_DSIG, "SignatureMethod")
        || references
            .iter()
            .any(|r| !is_el(doc, *r, NS_DSIG, "Reference"))
    {
        return Err(R::SignatureProfile);
    }
    if algorithm(doc, *c14n)? != EXC_C14N {
        return Err(R::Algorithm);
    }
    only_inclusive_namespaces(doc, *c14n)?;
    if !SIGNATURE_METHODS.contains(&algorithm(doc, *method)?) {
        return Err(R::Algorithm);
    }
    if !child_elements(doc, *method).is_empty() {
        return Err(R::SignatureProfile);
    }
    let [reference] = references else {
        return Err(R::SignatureProfile);
    };

    // The Reference: same-document fragment to the signed element only. Anything else (empty,
    // relative path, absolute URL, XPointer) is refused here, before bergshamra could resolve it.
    let expected_uri = format!("#{target_id}");
    if attr(doc, *reference, "URI") != Some(expected_uri.as_str()) {
        return Err(R::SignatureProfile);
    }
    let parts = child_elements(doc, *reference);
    let [transforms, digest_method, digest_value] = parts[..] else {
        return Err(R::SignatureProfile);
    };
    if !is_el(doc, transforms, NS_DSIG, "Transforms")
        || !is_el(doc, digest_method, NS_DSIG, "DigestMethod")
        || !is_el(doc, digest_value, NS_DSIG, "DigestValue")
    {
        return Err(R::SignatureProfile);
    }
    let transform_list = child_elements(doc, transforms);
    if transform_list
        .iter()
        .any(|t| !is_el(doc, *t, NS_DSIG, "Transform"))
    {
        return Err(R::SignatureProfile);
    }
    let algorithms = transform_list
        .iter()
        .map(|t| algorithm(doc, *t))
        .collect::<Result<Vec<_>, _>>()?;
    if algorithms.iter().any(|a| *a != ENVELOPED && *a != EXC_C14N) {
        return Err(R::Algorithm);
    }
    if algorithms != [ENVELOPED, EXC_C14N] {
        return Err(R::SignatureProfile);
    }
    if !child_elements(doc, transform_list[0]).is_empty() {
        return Err(R::SignatureProfile);
    }
    only_inclusive_namespaces(doc, transform_list[1])?;
    if !DIGEST_METHODS.contains(&algorithm(doc, digest_method)?) {
        return Err(R::Algorithm);
    }
    if !child_elements(doc, digest_method).is_empty() {
        return Err(R::SignatureProfile);
    }
    for value in [digest_value, signature_value] {
        if text_only(doc, value)
            .map_err(|_| R::SignatureProfile)?
            .is_empty()
        {
            return Err(R::SignatureProfile);
        }
    }

    // KeyInfo is only a hint for key ranking (keys come from configuration): X509Data with
    // certificates, or KeyName. No RetrievalMethod, KeyInfoReference, EncryptedKey, ...
    if let Some(ki) = key_info {
        for c in child_elements(doc, ki) {
            if is_el(doc, c, NS_DSIG, "KeyName") {
                text_only(doc, c).map_err(|_| R::SignatureProfile)?;
            } else if is_el(doc, c, NS_DSIG, "X509Data") {
                for cert in child_elements(doc, c) {
                    if !is_el(doc, cert, NS_DSIG, "X509Certificate") {
                        return Err(R::SignatureProfile);
                    }
                    text_only(doc, cert).map_err(|_| R::SignatureProfile)?;
                }
            } else {
                return Err(R::SignatureProfile);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Step 4: verification against the configured certificates only.
// ---------------------------------------------------------------------------------------------

/// The base64 body of a PEM certificate or an `X509Certificate` value, without whitespace.
fn cert_body(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_ascii_whitespace())
        .collect()
}

fn verify(doc: &Document<'_>, text: &str, pre: &Prechecked, certs: &[String]) -> Result<(), R> {
    if certs.is_empty() {
        return Err(R::UntrustedKey);
    }
    let mut keys = KeysManager::new();
    for pem in certs {
        let key = loader::load_x509_cert_pem(pem.as_bytes()).map_err(|_| R::UntrustedKey)?;
        keys.add_key(key);
    }
    let ctx = DsigContext::new(keys)
        .with_trusted_keys_only(true)
        .with_strict_verification(true)
        .with_require_reference_digests(true)
        .with_skip_time_checks(true);
    let results = bergshamra_dsig::verify::verify_all_document_with_source(&ctx, doc, Some(text))
        .map_err(|_| R::Signature)?;
    if results.len() != pre.signature_count {
        return Err(R::Signature);
    }
    let root = doc.document_element().ok_or(R::Structure)?;
    let assertion_result = results
        .get(pre.assertion_signature_index)
        .ok_or(R::Signature)?;
    check_result(
        doc,
        assertion_result,
        pre.assertion_signature,
        pre.assertion,
        certs,
    )?;
    if let (Some(sig), Some(index)) = (pre.response_signature, pre.response_signature_index) {
        let response_result = results.get(index).ok_or(R::Signature)?;
        check_result(doc, response_result, sig, root, certs)?;
    }
    Ok(())
}

/// A pinned signature's result: valid, the same signature node, one reference with a locally
/// verified digest that resolves to exactly the pre-checked element.
fn check_result(
    doc: &Document<'_>,
    result: &VerifyResult,
    signature: NodeId,
    target: NodeId,
    certs: &[String],
) -> Result<(), R> {
    match result {
        VerifyResult::Valid {
            signature_node,
            references,
            ..
        } => {
            let [
                VerifiedReference {
                    resolved_node,
                    digest_verified,
                    ..
                },
            ] = references.as_slice()
            else {
                return Err(R::Signature);
            };
            if *signature_node != signature
                || *resolved_node != Some(target)
                || !*digest_verified
                || !result.all_reference_digests_verified()
            {
                return Err(R::Signature);
            }
            Ok(())
        }
        VerifyResult::Invalid { .. } => Err(failure_reason(doc, signature, certs)),
    }
}

/// Reporting only (the document is refused either way): a failed signature whose `KeyInfo`
/// names a certificate that is not configured is reported as [`R::UntrustedKey`], every other
/// failure as [`R::Signature`].
fn failure_reason(doc: &Document<'_>, signature: NodeId, certs: &[String]) -> R {
    let configured: HashSet<String> = certs.iter().map(|c| cert_body(c)).collect();
    let foreign = first_child_named(doc, signature, NS_DSIG, "KeyInfo")
        .into_iter()
        .flat_map(|ki| children_named(doc, ki, NS_DSIG, "X509Data"))
        .flat_map(|xd| children_named(doc, xd, NS_DSIG, "X509Certificate"))
        .any(|c| !configured.contains(&cert_body(&doc.text_content_deep(c))));
    if foreign {
        R::UntrustedKey
    } else {
        R::Signature
    }
}

// ---------------------------------------------------------------------------------------------
// Step 5: extraction from the verified Assertion node.
// ---------------------------------------------------------------------------------------------

/// Reads [`SamlAssertionData`] from the verified `assertion` node (and the Response's own
/// attributes, Issuer and Status). Nothing outside the Assertion subtree is read for assertion
/// values.
pub fn extract(doc: &Document<'_>, assertion: NodeId) -> Result<SamlAssertionData, R> {
    let root = doc.parent(assertion).ok_or(R::Structure)?;
    let mut data = SamlAssertionData {
        response_destination: attr(doc, root, "Destination").map(str::to_owned),
        response_in_response_to: attr(doc, root, "InResponseTo").map(str::to_owned),
        issue_instant: opt_instant(attr(doc, root, "IssueInstant"))?,
        ..SamlAssertionData::default()
    };
    if let Some(issuer) = first_child_named(doc, root, NS_ASSERTION, "Issuer") {
        data.response_issuer = Some(text_only(doc, issuer)?);
    }
    if let Some(status) = first_child_named(doc, root, NS_PROTOCOL, "Status")
        && let Some(code) = first_child_named(doc, status, NS_PROTOCOL, "StatusCode")
    {
        data.status_code = attr(doc, code, "Value").unwrap_or_default().to_owned();
    }

    data.assertion_id = attr(doc, assertion, "ID").unwrap_or_default().to_owned();
    let issuer = first_child_named(doc, assertion, NS_ASSERTION, "Issuer").ok_or(R::Structure)?;
    data.issuer = text_only(doc, issuer)?;

    if let Some(subject) = first_child_named(doc, assertion, NS_ASSERTION, "Subject") {
        for c in child_elements(doc, subject) {
            if is_el(doc, c, NS_ASSERTION, "NameID") {
                if !data.name_id.is_empty() {
                    return Err(R::Structure);
                }
                data.name_id = text_only(doc, c)?;
                data.name_id_format = attr(doc, c, "Format").map(str::to_owned);
            } else if is_el(doc, c, NS_ASSERTION, "SubjectConfirmation") {
                let confirmation = subject_confirmation(doc, c)?;
                let bearer = confirmation.method == anvil_core::saml::validate::CM_BEARER;
                let have_bearer = data
                    .subject_confirmation
                    .as_ref()
                    .is_some_and(|s| s.method == anvil_core::saml::validate::CM_BEARER);
                if data.subject_confirmation.is_none() || (bearer && !have_bearer) {
                    data.subject_confirmation = Some(confirmation);
                }
            } else {
                // BaseID or anything else: not an identifier this SP accepts.
                return Err(R::Structure);
            }
        }
    }

    if let Some(conditions) = first_child_named(doc, assertion, NS_ASSERTION, "Conditions") {
        data.has_conditions = true;
        data.not_before = opt_instant(attr(doc, conditions, "NotBefore"))?;
        data.not_on_or_after = opt_instant(attr(doc, conditions, "NotOnOrAfter"))?;
        for restriction in children_named(doc, conditions, NS_ASSERTION, "AudienceRestriction") {
            let mut audiences = Vec::new();
            for a in child_elements(doc, restriction) {
                if !is_el(doc, a, NS_ASSERTION, "Audience") {
                    return Err(R::Structure);
                }
                audiences.push(text_only(doc, a)?);
            }
            data.audiences.push(audiences);
        }
    }

    for statement in children_named(doc, assertion, NS_ASSERTION, "AuthnStatement") {
        if !data.has_authn_statement {
            data.has_authn_statement = true;
            data.session_index = attr(doc, statement, "SessionIndex").map(str::to_owned);
        }
    }

    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for statement in children_named(doc, assertion, NS_ASSERTION, "AttributeStatement") {
        for a in child_elements(doc, statement) {
            if !is_el(doc, a, NS_ASSERTION, "Attribute") {
                return Err(R::Structure);
            }
            let mut values = Vec::new();
            for v in child_elements(doc, a) {
                if !is_el(doc, v, NS_ASSERTION, "AttributeValue") {
                    return Err(R::Structure);
                }
                values.push(text_only(doc, v)?);
            }
            // A text node directly in Attribute (outside AttributeValue) is not a value either.
            text_outside_elements(doc, a)?;
            let name = attr(doc, a, "Name").ok_or(R::Structure)?;
            let friendly = attr(doc, a, "FriendlyName").filter(|f| !f.is_empty() && *f != name);
            for key in std::iter::once(name).chain(friendly) {
                attributes
                    .entry(key.to_owned())
                    .or_default()
                    .extend(values.iter().cloned());
            }
        }
    }
    data.attributes = attributes;
    Ok(data)
}

/// Refuses comments, processing instructions and non-whitespace text directly inside `id`.
fn text_outside_elements(doc: &Document<'_>, id: NodeId) -> Result<(), R> {
    for c in doc.children_iter(id) {
        match doc.node_kind(c) {
            Some(NodeKind::Element(_)) => {}
            Some(NodeKind::Text(t)) | Some(NodeKind::CData(t)) if t.trim().is_empty() => {}
            _ => return Err(R::Structure),
        }
    }
    Ok(())
}

fn subject_confirmation(doc: &Document<'_>, id: NodeId) -> Result<SamlSubjectConfirmation, R> {
    let mut out = SamlSubjectConfirmation {
        method: attr(doc, id, "Method").unwrap_or_default().to_owned(),
        ..SamlSubjectConfirmation::default()
    };
    let data = children_named(doc, id, NS_ASSERTION, "SubjectConfirmationData");
    match data[..] {
        [] => {}
        [d] => {
            out.recipient = attr(doc, d, "Recipient").map(str::to_owned);
            out.in_response_to = attr(doc, d, "InResponseTo").map(str::to_owned);
            out.not_on_or_after = opt_instant(attr(doc, d, "NotOnOrAfter"))?;
            // Bearer confirmation data carries no elements (no KeyInfo, no wrapped content).
            if !child_elements(doc, d).is_empty() {
                return Err(R::Structure);
            }
        }
        _ => return Err(R::Structure),
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// IdP metadata.
// ---------------------------------------------------------------------------------------------

fn metadata(doc: &Document<'_>) -> Result<IdpMetadata, R> {
    let root = doc.document_element().ok_or(R::Structure)?;
    let entity = if is_el(doc, root, NS_METADATA, "EntityDescriptor") {
        root
    } else if is_el(doc, root, NS_METADATA, "EntitiesDescriptor") {
        let idps: Vec<NodeId> = children_named(doc, root, NS_METADATA, "EntityDescriptor")
            .into_iter()
            .filter(|e| first_child_named(doc, *e, NS_METADATA, "IDPSSODescriptor").is_some())
            .collect();
        let [only] = idps[..] else {
            return Err(R::Structure);
        };
        only
    } else {
        return Err(R::Structure);
    };

    let entity_id = attr(doc, entity, "entityID")
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .ok_or(R::Structure)?
        .to_owned();
    let idp = children_named(doc, entity, NS_METADATA, "IDPSSODescriptor");
    let [idp] = idp[..] else {
        return Err(R::Structure);
    };

    let sso_url = children_named(doc, idp, NS_METADATA, "SingleSignOnService")
        .into_iter()
        .find(|s| attr(doc, *s, "Binding") == Some(BINDING_HTTP_REDIRECT))
        .and_then(|s| attr(doc, s, "Location"))
        .map(str::trim)
        .ok_or(R::Structure)?;
    let parsed = url::Url::parse(sso_url).map_err(|_| R::Structure)?;
    if parsed.scheme() != "https" || parsed.host_str().is_none_or(str::is_empty) {
        return Err(R::Structure);
    }

    let mut signing_certs: Vec<String> = Vec::new();
    for kd in children_named(doc, idp, NS_METADATA, "KeyDescriptor") {
        if !matches!(attr(doc, kd, "use"), None | Some("signing")) {
            continue;
        }
        for ki in children_named(doc, kd, NS_DSIG, "KeyInfo") {
            for xd in children_named(doc, ki, NS_DSIG, "X509Data") {
                for c in children_named(doc, xd, NS_DSIG, "X509Certificate") {
                    let body = cert_body(&text_only(doc, c)?);
                    let der = b64std_decode(&body).map_err(|_| R::Structure)?;
                    if der.is_empty() {
                        return Err(R::Structure);
                    }
                    let pem = pem_certificate(&der);
                    if !signing_certs.contains(&pem) {
                        signing_certs.push(pem);
                    }
                }
            }
        }
    }
    if signing_certs.is_empty() {
        return Err(R::Structure);
    }
    Ok(IdpMetadata {
        entity_id,
        sso_url: sso_url.to_owned(),
        signing_certs,
    })
}

/// PEM `CERTIFICATE` armour, 64-column lines.
fn pem_certificate(der: &[u8]) -> String {
    let b64 = b64std(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_uri_detection() {
        for ok in [
            "urn:oasis:names:tc:SAML:2.0:assertion",
            "http://www.w3.org/2000/09/xmldsig#",
            "a+b.c-d:x",
        ] {
            assert!(is_absolute_uri(ok), "{ok}");
        }
        for bad in ["relative", "rel/ative", ":x", "1a:x", "a b:x", "", "#frag"] {
            assert!(!is_absolute_uri(bad), "{bad}");
        }
    }

    #[test]
    fn cert_body_strips_armour_and_whitespace() {
        assert_eq!(
            cert_body("-----BEGIN CERTIFICATE-----\nAB CD\r\nEF\n-----END CERTIFICATE-----\n"),
            "ABCDEF"
        );
        assert_eq!(cert_body("  AB\n CD "), "ABCD");
    }
}
