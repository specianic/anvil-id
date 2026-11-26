//! A software WebAuthn authenticator for integration tests (test code only, the same encoder as
//! `flow_passkey.rs` and `passkey_adapter.rs`): one P-256 credential that produces `none`
//! attestation registration responses and signed assertions in the `PublicKeyCredential.toJSON()`
//! shape.

#![allow(dead_code)]

use anvil_core::ports::PasskeyUser;
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use serde_json::json;
use uuid::Uuid;

fn b64(bytes: &[u8]) -> String {
    anvil_jose::encoding::b64url(bytes)
}

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

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_AT: u8 = 0x40;

/// One P-256 credential bound to a user handle.
pub struct SoftAuthenticator {
    key: EcdsaKeyPair,
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
    rng: SystemRandom,
}

impl SoftAuthenticator {
    pub fn new(user: &PasskeyUser) -> Self {
        let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("p256 key");
        let credential_id = Uuid::new_v4().as_bytes().to_vec();
        Self {
            key,
            credential_id,
            user_handle: user.id.0.as_bytes().to_vec(),
            rng: SystemRandom::new(),
        }
    }

    /// The credential id, base64url without padding (the encoding of WebAuthn JSON options).
    pub fn credential_id_b64(&self) -> String {
        b64(&self.credential_id)
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
    pub fn register(&self, challenge: &str, rp_id: &str, origin: &str, flags: u8) -> String {
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
    pub fn assert(
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
