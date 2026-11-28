//! Passkey sign-in through the built-in login page (AUTH-04, UI-02) on the selected backend
//! (`ANVILID_TEST_DB`): the passkey button (hidden without JavaScript, CSP allows only the
//! self-hosted webauthn.js), the flow-bound options endpoint, a full usernameless sign-in with a
//! software authenticator (test code only, copied from `passkey_adapter.rs`), and rejection of
//! garbage and of a replayed (already consumed) challenge.

mod support;
mod ui_helpers;

use anvil_cache::limiter::RateQuota;
use anvil_core::model::{AMR_HWK, AMR_MFA, AMR_USER, CredentialId, NewPasskey, SecretHash};
use anvil_core::ports::{Clock as _, PasskeyCeremonies, PasskeyUser};
use anvil_web::adapters::{WebauthnPasskeys, relying_party};
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use serde_json::json;
use support::{TestApp, TestResponse, csrf_from, json};
use ui_helpers::*;
use uuid::Uuid;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery";

fn b64(bytes: &[u8]) -> String {
    anvil_jose::encoding::b64url(bytes)
}

// ---------------------------------------------------------------------------------------------
// Minimal CBOR encoder and software authenticator (test code only)
// ---------------------------------------------------------------------------------------------

fn cbor_head(major: u8, len: u64) -> Vec<u8> {
    let m = major << 5;
    match len {
        0..=23 => vec![m | len as u8],
        24..=0xff => vec![m | 24, len as u8],
        0x100..=0xffff => {
            let mut v = vec![m | 25];
            v.extend_from_slice(&(len as u16).to_be_bytes());
            v
        }
        _ => {
            let mut v = vec![m | 26];
            v.extend_from_slice(&(len as u32).to_be_bytes());
            v
        }
    }
}

fn cbor_int(i: i64) -> Vec<u8> {
    if i >= 0 {
        cbor_head(0, i as u64)
    } else {
        cbor_head(1, (-1 - i) as u64)
    }
}

fn cbor_bytes(b: &[u8]) -> Vec<u8> {
    let mut v = cbor_head(2, b.len() as u64);
    v.extend_from_slice(b);
    v
}

fn cbor_text(s: &str) -> Vec<u8> {
    let mut v = cbor_head(3, s.len() as u64);
    v.extend_from_slice(s.as_bytes());
    v
}

fn cbor_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut v = cbor_head(5, entries.len() as u64);
    for (k, val) in entries {
        v.extend_from_slice(k);
        v.extend_from_slice(val);
    }
    v
}

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

/// One P-256 credential bound to a user handle.
struct SoftAuthenticator {
    key: EcdsaKeyPair,
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
    rng: SystemRandom,
}

impl SoftAuthenticator {
    fn new(user: &PasskeyUser) -> Self {
        let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("p256 key");
        let credential_id = Uuid::new_v4().as_bytes().to_vec();
        Self {
            key,
            credential_id,
            user_handle: user.id.0.as_bytes().to_vec(),
            rng: SystemRandom::new(),
        }
    }

    fn cose_key(&self) -> Vec<u8> {
        let point = self.key.public_key().as_ref();
        assert_eq!(point.len(), 65, "uncompressed P-256 point");
        cbor_map(&[
            (cbor_int(1), cbor_int(2)),  // kty: EC2
            (cbor_int(3), cbor_int(-7)), // alg: ES256
            (cbor_int(-1), cbor_int(1)), // crv: P-256
            (cbor_int(-2), cbor_bytes(&point[1..33])),
            (cbor_int(-3), cbor_bytes(&point[33..65])),
        ])
    }

    fn rp_id_hash(rp_id: &str) -> Vec<u8> {
        digest(&SHA256, rp_id.as_bytes()).as_ref().to_vec()
    }

    fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": kind,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        }))
        .expect("client data")
    }

    /// A registration response (`PublicKeyCredential.toJSON()` shape).
    fn register(&self, challenge: &str, rp_id: &str, origin: &str, flags: u8) -> String {
        let mut auth_data = Self::rp_id_hash(rp_id);
        auth_data.push(flags);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
        auth_data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend_from_slice(&self.cose_key());
        let attestation_object = cbor_map(&[
            (cbor_text("fmt"), cbor_text("none")),
            (cbor_text("attStmt"), cbor_map(&[])),
            (cbor_text("authData"), cbor_bytes(&auth_data)),
        ]);
        let client_data = Self::client_data("webauthn.create", challenge, origin);
        json!({
            "id": b64(&self.credential_id),
            "rawId": b64(&self.credential_id),
            "type": "public-key",
            "response": {
                "attestationObject": b64(&attestation_object),
                "clientDataJSON": b64(&client_data),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
        })
        .to_string()
    }

    /// An assertion response signed with this credential.
    fn assert(
        &self,
        challenge: &str,
        rp_id: &str,
        origin: &str,
        flags: u8,
        counter: u32,
    ) -> String {
        let mut auth_data = Self::rp_id_hash(rp_id);
        auth_data.push(flags);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let client_data = Self::client_data("webauthn.get", challenge, origin);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(digest(&SHA256, &client_data).as_ref());
        let signature = self.key.sign(&self.rng, &signed).expect("sign");
        json!({
            "id": b64(&self.credential_id),
            "rawId": b64(&self.credential_id),
            "type": "public-key",
            "response": {
                "authenticatorData": b64(&auth_data),
                "clientDataJSON": b64(&client_data),
                "signature": b64(signature.as_ref()),
                "userHandle": b64(&self.user_handle),
            },
            "clientExtensionResults": {},
        })
        .to_string()
    }
}

async fn app() -> TestApp {
    TestApp::with(|c| c.rate_limits.auth = RateQuota::per_minute(6000, 1000)).await
}

/// Registers alice and a soft passkey for her (stored through the storage port).
async fn alice_with_passkey(app: &TestApp) -> SoftAuthenticator {
    register(app, "", EMAIL, PASSWORD).await;
    let tenant = default_tenant(app);
    let user = app
        .storage()
        .users()
        .get_by_email(tenant.id, EMAIL)
        .await
        .expect("lookup")
        .expect("user");
    let rp = relying_party(&tenant, &app.issuer(None)).expect("relying party");
    let pk_user = PasskeyUser {
        id: user.id,
        name: EMAIL.to_owned(),
        display_name: "Alice".to_owned(),
    };
    let auth = SoftAuthenticator::new(&pk_user);
    let ch = WebauthnPasskeys
        .start_registration(&rp, &pk_user, &[])
        .expect("start");
    let options: serde_json::Value = serde_json::from_str(&ch.options_json).expect("json");
    let challenge = options["publicKey"]["challenge"]
        .as_str()
        .expect("challenge");
    let resp = auth.register(
        challenge,
        &rp.rp_id,
        &rp.origin,
        FLAG_UP | FLAG_UV | FLAG_AT,
    );
    let reg = WebauthnPasskeys
        .finish_registration(&rp, &resp, &ch.state_json)
        .expect("registration verifies");
    app.storage()
        .users()
        .create_passkey(
            tenant.id,
            user.id,
            &NewPasskey {
                id: CredentialId::new_v7(),
                credential_id: reg.credential_id,
                passkey_json: reg.passkey_json,
                counter: reg.counter,
                backup_eligible: reg.backup_eligible,
                label: "Laptop".into(),
                created_at: app.clock().now(),
            },
        )
        .await
        .expect("passkey");
    auth
}

/// The value of the first `attr="…"` after `id="{id}"`.
fn attr_after(html: &str, id: &str, attr: &str) -> String {
    let start = html
        .find(&format!("id=\"{id}\""))
        .unwrap_or_else(|| panic!("#{id} in page"));
    let marker = format!("{attr}=\"");
    let i = html[start..].find(&marker).expect("attribute") + start + marker.len();
    let end = html[i..].find('"').expect("quoted") + i;
    html[i..end].replace("&amp;", "&")
}

/// The passkey form of a login page: (options path, action path, csrf token).
fn passkey_form(app: &TestApp, page: &TestResponse) -> (String, String, String) {
    let html = page.html();
    (
        to_path(app, &attr_after(&html, "login-passkey", "data-options-url")),
        to_path(app, &attr_after(&html, "login-passkey", "action")),
        csrf_from(&html),
    )
}

/// POSTs the options request like webauthn.js and returns the challenge.
async fn challenge(app: &TestApp, options: &str, csrf: &str) -> String {
    let resp = app.post_form(options, &[("csrf_token", csrf)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    json(&resp)["publicKey"]["challenge"]
        .as_str()
        .expect("challenge")
        .to_owned()
}

fn rp_id() -> &'static str {
    "op.test"
}

fn origin() -> &'static str {
    "https://op.test"
}

#[tokio::test]
async fn login_page_offers_the_passkey_button_hidden_until_webauthn_js_runs() {
    let app = app().await;
    let resp = app.get("/ui/login").await;
    assert_eq!(resp.status, 200);
    let html = resp.html();
    // The password form is unchanged and first (it works without JavaScript).
    assert!(
        html.find("id=\"login\"").expect("login form")
            < html.find("id=\"login-passkey\"").expect("passkey form")
    );
    for needle in [
        "data-webauthn=\"authenticate\"",
        "id=\"login-passkey-submit\"",
        "data-webauthn-trigger hidden",
        "data-webauthn-status aria-live=\"polite\"",
        "<input type=\"hidden\" name=\"response\" value=\"\">",
        "<script src=\"/assets/webauthn.js\" defer></script>",
    ] {
        assert!(html.contains(needle), "{needle} in {html}");
    }
    let (options, action, _) = passkey_form(&app, &resp);
    assert!(
        options.starts_with("/ui/login/passkey/options?flow="),
        "{options}"
    );
    assert!(action.starts_with("/ui/login/passkey?flow="), "{action}");
    let csp = resp.header("content-security-policy").expect("csp");
    assert!(csp.contains("script-src 'self'"), "{csp}");
    assert!(csp.contains("connect-src 'self'"), "{csp}");
    assert!(!csp.contains("unsafe"), "{csp}");
}

#[tokio::test]
async fn options_are_discoverable_and_bound_to_the_flow() {
    let app = app().await;
    let page = app.get("/ui/login").await;
    let (options, _, csrf) = passkey_form(&app, &page);

    let resp = app.post_form(&options, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let body = json(&resp);
    assert!(body["publicKey"]["challenge"].is_string(), "{body}");
    assert_eq!(body["publicKey"]["rpId"], "op.test");
    assert!(
        body["publicKey"]["allowCredentials"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "usernameless: no allowCredentials ({body})"
    );

    // Without or with a wrong CSRF token, or without the flow cookie: 403.
    let resp = app.post_form(&options, &[]).await;
    assert_eq!(resp.status, 403);
    assert_eq!(json(&resp)["error"], "csrf");
    let resp = app.post_form(&options, &[("csrf_token", "wrong")]).await;
    assert_eq!(resp.status, 403);
    app.clear_cookies();
    let resp = app.post_form(&options, &[("csrf_token", &csrf)]).await;
    assert_eq!(resp.status, 403);
}

#[tokio::test]
async fn a_garbage_assertion_is_the_login_form_with_passkey_failed() {
    let app = app().await;
    alice_with_passkey(&app).await;
    let page = app.get("/ui/login").await;
    let (options, action, csrf) = passkey_form(&app, &page);
    challenge(&app, &options, &csrf).await;
    for garbage in ["", "not json", "{}", "{\"id\":\"x\",\"response\":{}}"] {
        // Post/Redirect/Get: followed like a browser.
        let resp = post_form_follow(
            &app,
            &action,
            &[("csrf_token", &csrf), ("response", garbage)],
        )
        .await;
        assert_eq!(resp.status, 400, "{garbage}: {}", resp.text());
        let html = resp.html();
        assert_eq!(
            message_keys(&html),
            vec!["login.passkey_failed".to_owned()],
            "{garbage}"
        );
        assert!(html.contains("id=\"login\""), "the sign-in form again");
        assert!(session_cookie(&app).is_none());
    }
    // Without the CSRF token: the csrf page.
    let resp = app.post_form(&action, &[("response", "{}")]).await;
    assert_eq!(resp.status, 403);
}

#[tokio::test]
async fn passkey_signs_in_and_a_consumed_challenge_cannot_be_replayed() {
    let app = app().await;
    let auth = alice_with_passkey(&app).await;
    let page = app.get("/ui/login").await;
    let (options, action, csrf) = passkey_form(&app, &page);

    // A valid assertion for this challenge, but a failed finish comes first: the challenge is
    // single use, so the valid assertion is now a replay and is rejected.
    let ch = challenge(&app, &options, &csrf).await;
    let assertion = auth.assert(&ch, rp_id(), origin(), FLAG_UP | FLAG_UV, 1);
    let resp = post_form_follow(
        &app,
        &action,
        &[("csrf_token", &csrf), ("response", "garbage")],
    )
    .await;
    assert_eq!(resp.status, 400);
    let resp = post_form_follow(
        &app,
        &action,
        &[("csrf_token", &csrf), ("response", &assertion)],
    )
    .await;
    assert_eq!(resp.status, 400, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["login.passkey_failed".to_owned()]
    );
    assert!(
        session_cookie(&app).is_none(),
        "replayed challenge signs nobody in"
    );

    // A fresh challenge in the same flow: signed in.
    let ch = challenge(&app, &options, &csrf).await;
    let assertion = auth.assert(&ch, rp_id(), origin(), FLAG_UP | FLAG_UV, 2);
    let resp = app
        .post_form(&action, &[("csrf_token", &csrf), ("response", &assertion)])
        .await;
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(
        message_keys(&resp.html()),
        vec!["login.signed_in".to_owned()]
    );
    let (_, value) = session_cookie(&app).expect("session cookie");
    let s = app
        .storage()
        .sessions()
        .get_active(
            default_tenant(&app).id,
            &SecretHash(anvil_jose::encoding::secret_hash(&value)),
            app.clock().now(),
        )
        .await
        .expect("lookup")
        .expect("session");
    assert_eq!(
        s.amr,
        vec![AMR_HWK.to_owned(), AMR_USER.to_owned(), AMR_MFA.to_owned()]
    );

    // The same assertion again in a new flow (whose challenge it was not made for): rejected.
    app.clear_cookies();
    let page = app.get("/ui/login").await;
    let (options, action, csrf) = passkey_form(&app, &page);
    challenge(&app, &options, &csrf).await;
    let resp =
        post_form_follow(&app, &action, &[("csrf_token", &csrf), ("response", &assertion)]).await;
    assert_eq!(resp.status, 400);
    assert!(session_cookie(&app).is_none());
}
