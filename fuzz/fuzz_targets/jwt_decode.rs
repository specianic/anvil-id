//! Compact-JWS parsing and verification (SEC-07).
//!
//! Input byte 0 selects the mode:
//! - even: the rest is an arbitrary token (lossy UTF-8) for `decode_header` and `verify_jwt`;
//!   neither may panic.
//! - odd: the rest is parsed as JSON; a JSON object is signed with the fixed key, and
//!   `verify_jwt` must accept it and return exactly the signed claims (round trip).
#![no_main]

use std::sync::OnceLock;

use anvil_jose::jws::MAX_JWS_LEN;
use anvil_jose::{Alg, Jwks, SigningKey, decode_header, generate_rs256, verify_jwt};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const ALLOWED: &[Alg] = &[Alg::RS256, Alg::PS256, Alg::ES256];

struct Fixture {
    key: SigningKey,
    jwks: Jwks,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let g = generate_rs256().expect("generate RS256 key");
        let key = SigningKey::from_pkcs8(&g.kid, g.alg, &g.pkcs8).expect("load generated key");
        Fixture {
            key,
            jwks: Jwks {
                keys: vec![g.public_jwk],
            },
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode % 2 == 0 {
        let token = String::from_utf8_lossy(rest);
        let _ = decode_header(&token);
        let _ = verify_jwt(&token, &f.jwks, ALLOWED);
        return;
    }

    let Ok(Value::Object(claims)) = serde_json::from_slice::<Value>(rest) else {
        return;
    };
    let token = f.key.sign_jwt(None, &claims).expect("sign object claims");
    if token.len() > MAX_JWS_LEN {
        assert!(verify_jwt(&token, &f.jwks, ALLOWED).is_err());
        return;
    }
    let header = decode_header(&token).expect("header of a signed token");
    assert_eq!(header.alg, "RS256");
    let verified = verify_jwt(&token, &f.jwks, ALLOWED).expect("verify a token we signed");
    assert_eq!(verified.claims, claims, "claims must round-trip");
    // The same token must be rejected when RS256 is not allowed.
    assert!(verify_jwt(&token, &f.jwks, &[Alg::ES256]).is_err());
});
