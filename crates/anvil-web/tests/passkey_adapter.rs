//! WebauthnPasskeys adapter (AUTH-04): relying-party derivation, option shapes, state round trip
//! and every rejection path.
//!
//! A minimal software authenticator (P-256, `none` attestation, hand-encoded CBOR) lives in this
//! test file so positive round trips and the security checks (challenge binding, origin, user
//! verification, credential binding, counter regression) run without a browser. The real browser
//! path is covered by Playwright with the CDP virtual authenticator (03-26).

use anvil_core::model::{Tenant, TenantId, TenantSettings, UserId};
use anvil_core::ports::{PasskeyCeremonies, PasskeyError, PasskeyUser, RelyingParty};
use anvil_web::adapters::{WebauthnPasskeys, relying_party};
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::DiscoverableAuthentication;

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn tenant(display_name: &str) -> Tenant {
    Tenant {
        id: TenantId::new_v7(),
        slug: "acme".to_owned(),
        display_name: display_name.to_owned(),
        host: None,
        settings: TenantSettings::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn rp() -> RelyingParty {
    relying_party(&tenant("Acme"), "https://op.test/t/acme").expect("relying party")
}

fn user() -> PasskeyUser {
    PasskeyUser {
        id: UserId(Uuid::now_v7()),
        name: "alice@example.com".to_owned(),
        display_name: "Alice".to_owned(),
    }
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn options(json: &str) -> Value {
    serde_json::from_str(json).expect("options json")
}

fn challenge_of(options_json: &str) -> String {
    options(options_json)["publicKey"]["challenge"]
        .as_str()
        .expect("challenge")
        .to_owned()
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

/// Registers a fresh soft credential for `user` and returns it with the stored passkey JSON.
fn registered(rp: &RelyingParty, user: &PasskeyUser) -> (SoftAuthenticator, String) {
    let auth = SoftAuthenticator::new(user);
    let ch = WebauthnPasskeys
        .start_registration(rp, user, &[])
        .expect("start");
    let resp = auth.register(
        &challenge_of(&ch.options_json),
        &rp.rp_id,
        &rp.origin,
        FLAG_UP | FLAG_UV | FLAG_AT,
    );
    let reg = WebauthnPasskeys
        .finish_registration(rp, &resp, &ch.state_json)
        .expect("registration verifies");
    (auth, reg.passkey_json)
}

// ---------------------------------------------------------------------------------------------
// Relying party
// ---------------------------------------------------------------------------------------------

#[test]
fn relying_party_from_path_issuer() {
    let rp = relying_party(&tenant("Acme Corp"), "https://op.test/t/acme").unwrap();
    assert_eq!(rp.rp_id, "op.test");
    assert_eq!(rp.origin, "https://op.test");
    assert_eq!(rp.name, "Acme Corp");
}

#[test]
fn relying_party_dev_localhost_keeps_port() {
    let rp = relying_party(&tenant("Dev"), "http://localhost:8080").unwrap();
    assert_eq!(rp.rp_id, "localhost");
    assert_eq!(rp.origin, "http://localhost:8080");
}

#[test]
fn relying_party_custom_host_issuer() {
    let rp = relying_party(&tenant("Acme"), "https://login.acme.test").unwrap();
    assert_eq!(rp.rp_id, "login.acme.test");
    assert_eq!(rp.origin, "https://login.acme.test");
}

#[test]
fn relying_party_rejects_ip_and_garbage_issuers() {
    let t = tenant("Acme");
    assert!(relying_party(&t, "http://127.0.0.1:8080").is_err());
    assert!(relying_party(&t, "not a url").is_err());
    assert!(relying_party(&t, "ftp://op.test").is_err());
}

// ---------------------------------------------------------------------------------------------
// Option shapes and state
// ---------------------------------------------------------------------------------------------

#[test]
fn registration_options_request_discoverable_uv_required_credentials() {
    let user = user();
    let excluded = vec![vec![1u8, 2, 3, 4], vec![9u8; 16]];
    let ch = WebauthnPasskeys
        .start_registration(&rp(), &user, &excluded)
        .unwrap();
    let opts = options(&ch.options_json);
    let pk = &opts["publicKey"];

    let sel = &pk["authenticatorSelection"];
    assert_eq!(sel["residentKey"], "required");
    assert_eq!(sel["requireResidentKey"], true);
    assert_eq!(sel["userVerification"], "required");

    let user_id = B64.decode(pk["user"]["id"].as_str().unwrap()).unwrap();
    assert_eq!(user_id, user.id.0.as_bytes());
    assert_eq!(pk["user"]["name"], "alice@example.com");
    assert_eq!(pk["user"]["displayName"], "Alice");

    assert_eq!(pk["rp"]["id"], "op.test");
    assert_eq!(pk["rp"]["name"], "Acme");

    let ids: Vec<Vec<u8>> = pk["excludeCredentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| B64.decode(d["id"].as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(ids, excluded);

    // Server-side state is not in the options.
    assert!(!ch.options_json.contains(&ch.state_json));
}

#[test]
fn registration_options_without_exclusions_omit_exclude_list() {
    let ch = WebauthnPasskeys
        .start_registration(&rp(), &user(), &[])
        .unwrap();
    let opts = options(&ch.options_json);
    let ex = &opts["publicKey"]["excludeCredentials"];
    assert!(ex.is_null() || ex.as_array().is_some_and(Vec::is_empty));
}

#[test]
fn discoverable_options_are_modal_without_allow_list() {
    let ch = WebauthnPasskeys.start_discoverable(&rp()).unwrap();
    let opts = options(&ch.options_json);
    assert!(opts.get("mediation").is_none(), "{opts}");
    let pk = &opts["publicKey"];
    let allow = &pk["allowCredentials"];
    assert!(allow.is_null() || allow.as_array().is_some_and(Vec::is_empty));
    assert_eq!(pk["userVerification"], "required");
    assert_eq!(pk["rpId"], "op.test");
}

#[test]
fn discoverable_state_round_trips_through_serde() {
    let ch = WebauthnPasskeys.start_discoverable(&rp()).unwrap();
    let state: DiscoverableAuthentication = serde_json::from_str(&ch.state_json).unwrap();
    let again = serde_json::to_string(&state).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&again).unwrap(),
        serde_json::from_str::<Value>(&ch.state_json).unwrap()
    );
}

#[test]
fn challenges_are_unique() {
    let a = WebauthnPasskeys.start_discoverable(&rp()).unwrap();
    let b = WebauthnPasskeys.start_discoverable(&rp()).unwrap();
    assert_ne!(challenge_of(&a.options_json), challenge_of(&b.options_json));
}

// ---------------------------------------------------------------------------------------------
// Positive round trips (software authenticator)
// ---------------------------------------------------------------------------------------------

#[test]
fn registration_and_discoverable_sign_in_round_trip() {
    let rp = rp();
    let user = user();
    let auth = SoftAuthenticator::new(&user);
    let ch = WebauthnPasskeys
        .start_registration(&rp, &user, &[])
        .unwrap();
    let resp = auth.register(
        &challenge_of(&ch.options_json),
        &rp.rp_id,
        &rp.origin,
        FLAG_UP | FLAG_UV | FLAG_AT,
    );
    let reg = WebauthnPasskeys
        .finish_registration(&rp, &resp, &ch.state_json)
        .unwrap();
    assert_eq!(reg.credential_id, auth.credential_id);
    assert_eq!(reg.counter, 0);
    assert!(!reg.backup_eligible);

    let ch = WebauthnPasskeys.start_discoverable(&rp).unwrap();
    let resp = auth.assert(
        &challenge_of(&ch.options_json),
        &rp.rp_id,
        &rp.origin,
        FLAG_UP | FLAG_UV,
        1,
    );
    let id = WebauthnPasskeys.identify(&resp).unwrap();
    assert_eq!(id.user_id, user.id);
    assert_eq!(id.credential_id, auth.credential_id);

    let ok = WebauthnPasskeys
        .finish_discoverable(&rp, &resp, &ch.state_json, &reg.passkey_json)
        .unwrap();
    assert_eq!(ok.counter, 1);
    assert!(ok.user_verified);
    assert!(!ok.backup_eligible);
    assert!(
        ok.updated_passkey_json.is_some(),
        "counter advanced: passkey must be saved"
    );
}

#[test]
fn dev_localhost_origin_registers() {
    let rp = relying_party(&tenant("Dev"), "http://localhost:8080").unwrap();
    let (_auth, passkey) = registered(&rp, &user());
    assert!(!passkey.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------------------------

const GARBAGE: [&str; 5] = [
    "",
    "null",
    "{}",
    "not json",
    r#"{"id":"x","rawId":"!!","type":"public-key"}"#,
];

#[test]
fn garbage_registration_input_is_invalid() {
    let rp = rp();
    let ch = WebauthnPasskeys
        .start_registration(&rp, &user(), &[])
        .unwrap();
    for g in GARBAGE {
        assert_eq!(
            WebauthnPasskeys.finish_registration(&rp, g, &ch.state_json),
            Err(PasskeyError::Invalid),
            "response {g:?}"
        );
        assert_eq!(
            WebauthnPasskeys.finish_registration(&rp, "{}", g),
            Err(PasskeyError::Invalid),
            "state {g:?}"
        );
    }
}

#[test]
fn garbage_assertion_input_is_invalid() {
    let rp = rp();
    let user = user();
    let (auth, passkey) = registered(&rp, &user);
    let ch = WebauthnPasskeys.start_discoverable(&rp).unwrap();
    let good = auth.assert(
        &challenge_of(&ch.options_json),
        &rp.rp_id,
        &rp.origin,
        FLAG_UP | FLAG_UV,
        1,
    );
    for g in GARBAGE {
        assert_eq!(
            WebauthnPasskeys.identify(g),
            Err(PasskeyError::Invalid),
            "{g:?}"
        );
        assert_eq!(
            WebauthnPasskeys.finish_discoverable(&rp, g, &ch.state_json, &passkey),
            Err(PasskeyError::Invalid),
            "response {g:?}"
        );
        assert_eq!(
            WebauthnPasskeys.finish_discoverable(&rp, &good, g, &passkey),
            Err(PasskeyError::Invalid),
            "state {g:?}"
        );
        assert_eq!(
            WebauthnPasskeys.finish_discoverable(&rp, &good, &ch.state_json, g),
            Err(PasskeyError::Invalid),
            "stored passkey {g:?}"
        );
    }
}

#[test]
fn identify_rejects_missing_or_non_uuid_user_handle() {
    let rp = rp();
    let user = user();
    let auth = SoftAuthenticator::new(&user);
    let resp = auth.assert("AAAA", &rp.rp_id, &rp.origin, FLAG_UP | FLAG_UV, 1);
    let mut v: Value = serde_json::from_str(&resp).unwrap();
    v["response"]["userHandle"] = Value::Null;
    assert_eq!(
        WebauthnPasskeys.identify(&v.to_string()),
        Err(PasskeyError::Invalid)
    );
    v["response"]["userHandle"] = json!(b64(b"short"));
    assert_eq!(
        WebauthnPasskeys.identify(&v.to_string()),
        Err(PasskeyError::Invalid)
    );
}

#[test]
fn registration_with_state_of_another_challenge_is_invalid() {
    let rp = rp();
    let user = user();
    let auth = SoftAuthenticator::new(&user);
    let a = WebauthnPasskeys
        .start_registration(&rp, &user, &[])
        .unwrap();
    let b = WebauthnPasskeys
        .start_registration(&rp, &user, &[])
        .unwrap();
    let resp = auth.register(
        &challenge_of(&a.options_json),
        &rp.rp_id,
        &rp.origin,
        FLAG_UP | FLAG_UV | FLAG_AT,
    );
    assert_eq!(
        WebauthnPasskeys.finish_registration(&rp, &resp, &b.state_json),
        Err(PasskeyError::Invalid)
    );
}

#[test]
fn registration_from_wrong_origin_is_invalid() {
    let rp = rp();
    let user = user();
    let auth = SoftAuthenticator::new(&user);
    let ch = WebauthnPasskeys
        .start_registration(&rp, &user, &[])
        .unwrap();
    let resp = auth.register(
        &challenge_of(&ch.options_json),
        &rp.rp_id,
        "https://evil.test",
        FLAG_UP | FLAG_UV | FLAG_AT,
    );
    assert_eq!(
        WebauthnPasskeys.finish_registration(&rp, &resp, &ch.state_json),
        Err(PasskeyError::Invalid)
    );
}

#[test]
fn registration_without_user_verification_is_invalid() {
    let rp = rp();
    let user = user();
    let auth = SoftAuthenticator::new(&user);
    let ch = WebauthnPasskeys
        .start_registration(&rp, &user, &[])
        .unwrap();
    let resp = auth.register(
        &challenge_of(&ch.options_json),
        &rp.rp_id,
        &rp.origin,
        FLAG_UP | FLAG_AT,
    );
    assert_eq!(
        WebauthnPasskeys.finish_registration(&rp, &resp, &ch.state_json),
        Err(PasskeyError::Invalid)
    );
}

#[test]
fn registration_for_another_rp_id_is_invalid() {
    let rp = rp();
    let user = user();
    let auth = SoftAuthenticator::new(&user);
    let ch = WebauthnPasskeys
        .start_registration(&rp, &user, &[])
        .unwrap();
    let resp = auth.register(
        &challenge_of(&ch.options_json),
        "evil.test",
        &rp.origin,
        FLAG_UP | FLAG_UV | FLAG_AT,
    );
    assert_eq!(
        WebauthnPasskeys.finish_registration(&rp, &resp, &ch.state_json),
        Err(PasskeyError::Invalid)
    );
}

#[test]
fn assertion_with_state_of_another_challenge_is_invalid() {
    let rp = rp();
    let user = user();
    let (auth, passkey) = registered(&rp, &user);
    let a = WebauthnPasskeys.start_discoverable(&rp).unwrap();
    let b = WebauthnPasskeys.start_discoverable(&rp).unwrap();
    let resp = auth.assert(
        &challenge_of(&a.options_json),
        &rp.rp_id,
        &rp.origin,
        FLAG_UP | FLAG_UV,
        1,
    );
    assert_eq!(
        WebauthnPasskeys.finish_discoverable(&rp, &resp, &b.state_json, &passkey),
        Err(PasskeyError::Invalid)
    );
}

#[test]
fn assertion_from_wrong_origin_is_invalid() {
    let rp = rp();
    let user = user();
    let (auth, passkey) = registered(&rp, &user);
    let ch = WebauthnPasskeys.start_discoverable(&rp).unwrap();
    let resp = auth.assert(
        &challenge_of(&ch.options_json),
        &rp.rp_id,
        "https://evil.test",
        FLAG_UP | FLAG_UV,
        1,
    );
    assert_eq!(
        WebauthnPasskeys.finish_discoverable(&rp, &resp, &ch.state_json, &passkey),
        Err(PasskeyError::Invalid)
    );
}

#[test]
fn assertion_without_user_verification_is_invalid() {
    let rp = rp();
    let user = user();
    let (auth, passkey) = registered(&rp, &user);
    let ch = WebauthnPasskeys.start_discoverable(&rp).unwrap();
    let resp = auth.assert(
        &challenge_of(&ch.options_json),
        &rp.rp_id,
        &rp.origin,
        FLAG_UP,
        1,
    );
    assert_eq!(
        WebauthnPasskeys.finish_discoverable(&rp, &resp, &ch.state_json, &passkey),
        Err(PasskeyError::Invalid)
    );
}

#[test]
fn assertion_signed_by_another_key_is_invalid() {
    let rp = rp();
    let user = user();
    let (auth, passkey) = registered(&rp, &user);
    // Same credential id and user handle, different private key.
    let mut forger = SoftAuthenticator::new(&user);
    forger.credential_id = auth.credential_id.clone();
    let ch = WebauthnPasskeys.start_discoverable(&rp).unwrap();
    let resp = forger.assert(
        &challenge_of(&ch.options_json),
        &rp.rp_id,
        &rp.origin,
        FLAG_UP | FLAG_UV,
        1,
    );
    assert_eq!(
        WebauthnPasskeys.finish_discoverable(&rp, &resp, &ch.state_json, &passkey),
        Err(PasskeyError::Invalid)
    );
}

#[test]
fn assertion_against_another_stored_passkey_is_invalid() {
    let rp = rp();
    let user = user();
    let (auth, _passkey) = registered(&rp, &user);
    let (_other, other_passkey) = registered(&rp, &user);
    let ch = WebauthnPasskeys.start_discoverable(&rp).unwrap();
    let resp = auth.assert(
        &challenge_of(&ch.options_json),
        &rp.rp_id,
        &rp.origin,
        FLAG_UP | FLAG_UV,
        1,
    );
    assert_eq!(
        WebauthnPasskeys.finish_discoverable(&rp, &resp, &ch.state_json, &other_passkey),
        Err(PasskeyError::Invalid)
    );
}

#[test]
fn counter_regression_is_possible_clone() {
    let rp = rp();
    let user = user();
    let (auth, passkey) = registered(&rp, &user);

    let ch = WebauthnPasskeys.start_discoverable(&rp).unwrap();
    let resp = auth.assert(
        &challenge_of(&ch.options_json),
        &rp.rp_id,
        &rp.origin,
        FLAG_UP | FLAG_UV,
        5,
    );
    let ok = WebauthnPasskeys
        .finish_discoverable(&rp, &resp, &ch.state_json, &passkey)
        .unwrap();
    let stored = ok.updated_passkey_json.expect("counter advanced");

    for counter in [5, 3] {
        let ch = WebauthnPasskeys.start_discoverable(&rp).unwrap();
        let resp = auth.assert(
            &challenge_of(&ch.options_json),
            &rp.rp_id,
            &rp.origin,
            FLAG_UP | FLAG_UV,
            counter,
        );
        assert_eq!(
            WebauthnPasskeys.finish_discoverable(&rp, &resp, &ch.state_json, &stored),
            Err(PasskeyError::PossibleClone),
            "counter {counter}"
        );
    }
}
