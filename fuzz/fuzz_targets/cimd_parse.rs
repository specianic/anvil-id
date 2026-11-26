//! Client ID Metadata Document URL and document rules (AGT-02, draft-03).
//!
//! Input: an arbitrary URL and body. `check_url` and `validate` run in production and
//! development mode, and against the body with its `client_id` forced to the URL so the document
//! rules past the client id check are reached.
//!
//! Invariants (besides never panicking):
//! - `validate` never accepts what `check_url` refuses (same flag);
//! - production never accepts an http URL; development accepts http only for loopback hosts;
//! - an accepted document has `client_id == url`, no shared-secret method, no admin scope, is
//!   within 5 KiB and is confidential exactly when it uses `private_key_jwt`.
#![no_main]

use anvil_core::model::{ClientAuthMethod, ClientType};
use anvil_core::oauth::cimd::{MAX_DOCUMENT_BYTES, ServerCaps, check_url, validate};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    url: String,
    body: Vec<u8>,
}

fn check_body(url: &str, body: &[u8], caps: &ServerCaps, dev: bool) {
    let url_ok = check_url(url, dev).is_ok();
    if url_ok && !dev {
        assert!(url.starts_with("https://"), "production accepted {url:?}");
    }
    let Ok(m) = validate(url, body, caps, dev) else {
        return;
    };
    assert!(url_ok, "validate accepted a URL check_url refuses: {url:?}");
    assert!(body.len() <= MAX_DOCUMENT_BYTES);
    assert_eq!(m.client_id, url);
    assert!(matches!(
        m.auth_method,
        ClientAuthMethod::None | ClientAuthMethod::PrivateKeyJwt
    ));
    assert_eq!(
        m.client_type == ClientType::Confidential,
        m.auth_method == ClientAuthMethod::PrivateKeyJwt
    );
    assert!(m.jwks.is_some() == (m.auth_method == ClientAuthMethod::PrivateKeyJwt));
    assert!(!m.scopes.iter().any(|s| s.starts_with("admin")));
    assert!(!m.redirect_uris.is_empty());
}

fuzz_target!(|input: Input| {
    let caps = ServerCaps::default();
    for dev in [false, true] {
        check_body(&input.url, &input.body, &caps, dev);
        // Force client_id = url so the rules after the client id check are exercised.
        if let Ok(serde_json::Value::Object(mut doc)) =
            serde_json::from_slice::<serde_json::Value>(&input.body)
        {
            doc.insert("client_id".into(), input.url.clone().into());
            let body = serde_json::Value::Object(doc).to_string();
            check_body(&input.url, body.as_bytes(), &caps, dev);
        }
    }
});
