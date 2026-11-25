//! `private_key_jwt` client-assertion verification and HTTP Basic client credentials (SEC-07).
//!
//! - `Raw`: an arbitrary assertion string; `verify_client_assertion` must not panic.
//! - `Signed`: claims built from fuzzer choices are signed with the client's registered key, and
//!   the verifier's verdict must equal an independent model of the RFC 7523 rules
//!   (iss == sub == client_id, aud exactly the issuer, exp window, nbf/iat not in the future,
//!   jti present and at most 256 bytes, typ absent or `client-authentication+jwt`).
//! - `parse_basic` gets an arbitrary header (no panic; a success has non-empty parts) and a
//!   well-formed header built from arbitrary credentials (must round-trip).
#![no_main]

use std::sync::OnceLock;

use anvil_core::service::client_auth::parse_basic;
use anvil_jose::{AssertionRules, Jwks, SigningKey, generate_rs256, verify_client_assertion};
use arbitrary::Arbitrary;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value, json};
use time::{Duration, OffsetDateTime};

const ISSUER: &str = "https://op.example.test";
const CLIENT_ID: &str = "client-1";
const NOW: i64 = 1_800_000_000;
const MAX_LIFETIME: i64 = 300;
const LEEWAY: i64 = 30;
const TYP: &str = "client-authentication+jwt";

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

#[derive(Arbitrary, Debug)]
enum StrClaim {
    Correct,
    Other(String),
    Number(i64),
    Absent,
}

#[derive(Arbitrary, Debug)]
enum AudClaim {
    Issuer,
    IssuerArray,
    IssuerPlus(String),
    Other(String),
    Number(i64),
    Absent,
}

#[derive(Arbitrary, Debug)]
enum TimeClaim {
    /// Seconds relative to NOW.
    Offset(i32),
    Fractional(f32),
    Text(String),
    Absent,
}

#[derive(Arbitrary, Debug)]
enum Typ {
    Absent,
    Expected,
    Upper,
    Other(String),
}

#[derive(Arbitrary, Debug)]
struct Claims {
    typ: Typ,
    iss: StrClaim,
    sub: StrClaim,
    aud: AudClaim,
    exp: TimeClaim,
    nbf: TimeClaim,
    iat: TimeClaim,
    jti: StrClaim,
}

#[derive(Arbitrary, Debug)]
enum Input {
    Raw(String),
    Signed(Claims),
    BasicRaw(String),
    BasicCredentials { id: String, secret: String },
}

fn rules() -> AssertionRules<'static> {
    AssertionRules {
        issuer: ISSUER,
        client_id: CLIENT_ID,
        now: OffsetDateTime::from_unix_timestamp(NOW).expect("fixed now"),
        max_lifetime: Duration::seconds(MAX_LIFETIME),
        leeway: Duration::seconds(LEEWAY),
    }
}

fn str_value(c: &StrClaim, correct: &str) -> Option<Value> {
    match c {
        StrClaim::Correct => Some(json!(correct)),
        StrClaim::Other(s) => Some(json!(s)),
        StrClaim::Number(n) => Some(json!(n)),
        StrClaim::Absent => None,
    }
}

fn aud_value(a: &AudClaim) -> Option<Value> {
    match a {
        AudClaim::Issuer => Some(json!(ISSUER)),
        AudClaim::IssuerArray => Some(json!([ISSUER])),
        AudClaim::IssuerPlus(s) => Some(json!([ISSUER, s])),
        AudClaim::Other(s) => Some(json!(s)),
        AudClaim::Number(n) => Some(json!(n)),
        AudClaim::Absent => None,
    }
}

fn time_value(t: &TimeClaim) -> Option<Value> {
    match t {
        TimeClaim::Offset(o) => Some(json!(NOW + i64::from(*o))),
        TimeClaim::Fractional(f) => {
            let v = NOW as f64 + f64::from(*f);
            // Non-finite floats serialise as null.
            Some(serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number))
        }
        TimeClaim::Text(s) => Some(json!(s)),
        TimeClaim::Absent => None,
    }
}

/// Whole-second NumericDate as the verifier reads it, or Err for an invalid value.
fn model_time(v: Option<&Value>) -> Result<Option<i64>, ()> {
    match v {
        None => Ok(None),
        Some(v) => v
            .as_i64()
            .or_else(|| v.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))
            // Outside the representable OffsetDateTime range the claim is invalid.
            .filter(|s| OffsetDateTime::from_unix_timestamp(*s).is_ok())
            .map(Some)
            .ok_or(()),
    }
}

fn expected_accept(typ: Option<&str>, c: &Map<String, Value>) -> bool {
    let s = |name: &str| c.get(name).and_then(Value::as_str);
    let typ_ok = typ.is_none_or(|t| t.eq_ignore_ascii_case(TYP));
    let aud_ok = match c.get("aud") {
        Some(Value::String(a)) => a == ISSUER,
        Some(Value::Array(a)) => matches!(a.as_slice(), [Value::String(x)] if x == ISSUER),
        _ => false,
    };
    let (Ok(exp), Ok(nbf), Ok(iat)) = (
        model_time(c.get("exp")),
        model_time(c.get("nbf")),
        model_time(c.get("iat")),
    ) else {
        return false;
    };
    let exp_ok = exp.is_some_and(|e| e > NOW - LEEWAY && e <= NOW + MAX_LIFETIME);
    let nbf_ok = nbf.is_none_or(|n| n <= NOW + LEEWAY);
    let iat_ok = iat.is_none_or(|i| i <= NOW + LEEWAY);
    let jti_ok = s("jti").is_some_and(|j| !j.is_empty() && j.len() <= 256);
    typ_ok
        && s("iss") == Some(CLIENT_ID)
        && s("sub") == Some(CLIENT_ID)
        && aud_ok
        && exp_ok
        && nbf_ok
        && iat_ok
        && jti_ok
}

fn signed(f: &Fixture, c: &Claims) {
    let typ = match &c.typ {
        Typ::Absent => None,
        Typ::Expected => Some(TYP.to_owned()),
        Typ::Upper => Some(TYP.to_ascii_uppercase()),
        Typ::Other(s) => Some(s.clone()),
    };
    let mut claims = Map::new();
    let mut put = |name: &str, v: Option<Value>| {
        if let Some(v) = v {
            claims.insert(name.to_owned(), v);
        }
    };
    put("iss", str_value(&c.iss, CLIENT_ID));
    put("sub", str_value(&c.sub, CLIENT_ID));
    put("aud", aud_value(&c.aud));
    put("exp", time_value(&c.exp));
    put("nbf", time_value(&c.nbf));
    put("iat", time_value(&c.iat));
    put("jti", str_value(&c.jti, "jti-1"));

    let token = f
        .key
        .sign_jwt(typ.as_deref(), &claims)
        .expect("sign object claims");
    let result = verify_client_assertion(&token, &f.jwks, &rules());
    let expected = token.len() <= anvil_jose::jws::MAX_JWS_LEN && expected_accept(typ.as_deref(), &claims);
    assert_eq!(
        result.is_ok(),
        expected,
        "verdict {result:?} disagrees with the model for typ={typ:?} claims={claims:?}"
    );
    if let Ok(v) = result {
        assert_eq!(Some(v.jti.as_str()), claims.get("jti").and_then(Value::as_str));
    }
}

fn basic_roundtrip(id: &str, secret: &str) {
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    let header = format!("Basic {}", STANDARD.encode(format!("{}:{}", enc(id), enc(secret))));
    match parse_basic(&header) {
        Ok((pid, psecret)) => {
            assert_eq!((pid.as_str(), psecret.as_str()), (id, secret));
        }
        Err(_) => assert!(
            id.is_empty() || secret.is_empty(),
            "well-formed Basic header rejected"
        ),
    }
}

fuzz_target!(|input: Input| {
    let f = fixture();
    match input {
        Input::Raw(s) => {
            let _ = verify_client_assertion(&s, &f.jwks, &rules());
        }
        Input::Signed(c) => signed(f, &c),
        Input::BasicRaw(h) => {
            if let Ok((id, secret)) = parse_basic(&h) {
                assert!(!id.is_empty() && !secret.is_empty());
            }
        }
        Input::BasicCredentials { id, secret } => basic_roundtrip(&id, &secret),
    }
});
