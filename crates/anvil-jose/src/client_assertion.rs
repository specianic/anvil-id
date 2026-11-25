//! `private_key_jwt` client assertion verification (RFC 7523 §3, RFC 7521, with the audience
//! rules of the 2025 JWT client-authentication update: `aud` is the issuer identifier only).
//!
//! Claims are checked explicitly here; jsonwebtoken's `Validation` is not used because it accepts
//! an `aud` array that merely contains the expected value.
//! jti replay is NOT checked here: the caller records the returned jti through its storage port.

use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime};

use crate::JoseError;
use crate::jwk::Jwks;
use crate::jws::verify_jwt;
use crate::keys::Alg;

/// The only explicit `typ` accepted for client assertions (absent `typ` is also accepted).
pub const CLIENT_ASSERTION_TYP: &str = "client-authentication+jwt";

const ALLOWED_ALGS: &[Alg] = &[Alg::RS256, Alg::PS256, Alg::ES256];
const MAX_JTI_LEN: usize = 256;

/// Validation context for one assertion.
#[derive(Clone, Debug)]
pub struct AssertionRules<'a> {
    /// The OP issuer identifier; `aud` must be exactly this (string or one-element array).
    pub issuer: &'a str,
    /// The authenticated client's id; `iss` and `sub` must both equal it.
    pub client_id: &'a str,
    pub now: OffsetDateTime,
    /// Maximum distance of `exp` into the future (5 minutes).
    pub max_lifetime: Duration,
    /// Clock-skew allowance for past `exp` and future `nbf`/`iat` (30 seconds).
    pub leeway: Duration,
}

/// A verified assertion: the caller must record `jti` until `exp` to prevent replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAssertion {
    pub jti: String,
    pub exp: OffsetDateTime,
}

pub(crate) fn numeric_date(
    claims: &Map<String, Value>,
    name: &str,
    err: &'static str,
) -> Result<Option<OffsetDateTime>, JoseError> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => {
            // NumericDate may be fractional; truncate to whole seconds.
            let secs = v
                .as_i64()
                .or_else(|| v.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))
                .ok_or(JoseError::InvalidClaim(err))?;
            OffsetDateTime::from_unix_timestamp(secs)
                .map(Some)
                .map_err(|_| JoseError::InvalidClaim(err))
        }
    }
}

fn str_claim<'c>(claims: &'c Map<String, Value>, name: &str) -> Option<&'c str> {
    claims.get(name).and_then(Value::as_str)
}

fn aud_is_exactly(aud: Option<&Value>, issuer: &str) -> bool {
    match aud {
        Some(Value::String(s)) => s == issuer,
        Some(Value::Array(a)) => matches!(a.as_slice(), [Value::String(s)] if s == issuer),
        _ => false,
    }
}

/// Verify a client assertion signed by one of the client's registered keys.
pub fn verify_client_assertion(
    assertion: &str,
    client_jwks: &Jwks,
    rules: &AssertionRules,
) -> Result<VerifiedAssertion, JoseError> {
    let jwt = verify_jwt(assertion, client_jwks, ALLOWED_ALGS)?;
    if let Some(typ) = jwt.header.typ.as_deref()
        && !typ.eq_ignore_ascii_case(CLIENT_ASSERTION_TYP)
    {
        return Err(JoseError::InvalidClaim("typ"));
    }
    let c = &jwt.claims;
    if str_claim(c, "iss") != Some(rules.client_id) {
        return Err(JoseError::InvalidClaim("iss"));
    }
    if str_claim(c, "sub") != Some(rules.client_id) {
        return Err(JoseError::InvalidClaim("sub"));
    }
    if !aud_is_exactly(c.get("aud"), rules.issuer) {
        return Err(JoseError::InvalidClaim("aud"));
    }
    let exp = numeric_date(c, "exp", "exp")?.ok_or(JoseError::InvalidClaim("exp"))?;
    if exp <= rules.now - rules.leeway {
        return Err(JoseError::Expired);
    }
    if exp > rules.now + rules.max_lifetime {
        return Err(JoseError::InvalidClaim("exp"));
    }
    if let Some(nbf) = numeric_date(c, "nbf", "nbf")?
        && nbf > rules.now + rules.leeway
    {
        return Err(JoseError::InvalidClaim("nbf"));
    }
    if let Some(iat) = numeric_date(c, "iat", "iat")?
        && iat > rules.now + rules.leeway
    {
        return Err(JoseError::InvalidClaim("iat"));
    }
    let jti = str_claim(c, "jti")
        .filter(|j| !j.is_empty() && j.len() <= MAX_JTI_LEN)
        .ok_or(JoseError::InvalidClaim("jti"))?;
    Ok(VerifiedAssertion {
        jti: jti.to_owned(),
        exp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::test_keys::{TestKey, es256, rsa};
    use serde_json::json;

    const ISSUER: &str = "https://op.example.test";
    const TOKEN_ENDPOINT: &str = "https://op.example.test/token";
    const CLIENT: &str = "client-1";

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn rules() -> AssertionRules<'static> {
        AssertionRules {
            issuer: ISSUER,
            client_id: CLIENT,
            now: now(),
            max_lifetime: Duration::minutes(5),
            leeway: Duration::seconds(30),
        }
    }

    fn ts(offset_secs: i64) -> i64 {
        now().unix_timestamp() + offset_secs
    }

    fn good_claims() -> Value {
        json!({"iss": CLIENT, "sub": CLIENT, "aud": ISSUER, "exp": ts(60), "iat": ts(0), "jti": "j-1"})
    }

    fn with(mut base: Value, key: &str, v: Value) -> Value {
        base[key] = v;
        base
    }

    fn without(mut base: Value, key: &str) -> Value {
        base.as_object_mut().unwrap().remove(key);
        base
    }

    fn jwks(k: &TestKey) -> Jwks {
        Jwks {
            keys: vec![k.jwk.clone()],
        }
    }

    fn check(
        k: &TestKey,
        typ: Option<&str>,
        claims: &Value,
    ) -> Result<VerifiedAssertion, JoseError> {
        let t = k.signer.sign_jwt(typ, claims).unwrap();
        verify_client_assertion(&t, &jwks(k), &rules())
    }

    #[test]
    fn accepts_valid_assertions() {
        let k = rsa(Alg::RS256);
        let v = check(&k, None, &good_claims()).unwrap();
        assert_eq!(v.jti, "j-1");
        assert_eq!(v.exp.unix_timestamp(), ts(60));
        assert!(check(&k, Some("client-authentication+jwt"), &good_claims()).is_ok());
        assert!(check(&k, None, &with(good_claims(), "aud", json!([ISSUER]))).is_ok());
        assert!(check(&es256(), None, &good_claims()).is_ok());
        assert!(check(&rsa(Alg::PS256), None, &good_claims()).is_ok());
    }

    #[test]
    fn rejects_token_endpoint_audience() {
        let k = rsa(Alg::RS256);
        let c = with(good_claims(), "aud", json!(TOKEN_ENDPOINT));
        assert_eq!(
            check(&k, None, &c).unwrap_err(),
            JoseError::InvalidClaim("aud")
        );
        let c = with(good_claims(), "aud", json!([TOKEN_ENDPOINT]));
        assert_eq!(
            check(&k, None, &c).unwrap_err(),
            JoseError::InvalidClaim("aud")
        );
    }

    #[test]
    fn rejects_audience_array_with_extra_values() {
        let k = rsa(Alg::RS256);
        let c = with(good_claims(), "aud", json!([ISSUER, "other"]));
        assert_eq!(
            check(&k, None, &c).unwrap_err(),
            JoseError::InvalidClaim("aud")
        );
        let c = with(good_claims(), "aud", json!([]));
        assert_eq!(
            check(&k, None, &c).unwrap_err(),
            JoseError::InvalidClaim("aud")
        );
        let c = without(good_claims(), "aud");
        assert_eq!(
            check(&k, None, &c).unwrap_err(),
            JoseError::InvalidClaim("aud")
        );
    }

    #[test]
    fn rejects_bad_exp() {
        let k = rsa(Alg::RS256);
        let far = with(good_claims(), "exp", json!(ts(5 * 60 + 1)));
        assert_eq!(
            check(&k, None, &far).unwrap_err(),
            JoseError::InvalidClaim("exp")
        );
        let past = with(good_claims(), "exp", json!(ts(-31)));
        assert_eq!(check(&k, None, &past).unwrap_err(), JoseError::Expired);
        let missing = without(good_claims(), "exp");
        assert_eq!(
            check(&k, None, &missing).unwrap_err(),
            JoseError::InvalidClaim("exp")
        );
        let string = with(good_claims(), "exp", json!("soon"));
        assert_eq!(
            check(&k, None, &string).unwrap_err(),
            JoseError::InvalidClaim("exp")
        );
        // Within leeway and at the lifetime bound: accepted.
        assert!(check(&k, None, &with(good_claims(), "exp", json!(ts(-29)))).is_ok());
        assert!(check(&k, None, &with(good_claims(), "exp", json!(ts(300)))).is_ok());
    }

    #[test]
    fn rejects_bad_jti() {
        let k = rsa(Alg::RS256);
        let missing = without(good_claims(), "jti");
        assert_eq!(
            check(&k, None, &missing).unwrap_err(),
            JoseError::InvalidClaim("jti")
        );
        let empty = with(good_claims(), "jti", json!(""));
        assert_eq!(
            check(&k, None, &empty).unwrap_err(),
            JoseError::InvalidClaim("jti")
        );
        let number = with(good_claims(), "jti", json!(5));
        assert_eq!(
            check(&k, None, &number).unwrap_err(),
            JoseError::InvalidClaim("jti")
        );
    }

    #[test]
    fn rejects_iss_sub_mismatch() {
        let k = rsa(Alg::RS256);
        let c = with(good_claims(), "iss", json!("someone-else"));
        assert_eq!(
            check(&k, None, &c).unwrap_err(),
            JoseError::InvalidClaim("iss")
        );
        let c = with(good_claims(), "sub", json!("someone-else"));
        assert_eq!(
            check(&k, None, &c).unwrap_err(),
            JoseError::InvalidClaim("sub")
        );
        // iss == sub but != client_id.
        let c = with(with(good_claims(), "iss", json!("x")), "sub", json!("x"));
        assert_eq!(
            check(&k, None, &c).unwrap_err(),
            JoseError::InvalidClaim("iss")
        );
    }

    #[test]
    fn rejects_other_typ() {
        let k = rsa(Alg::RS256);
        assert_eq!(
            check(&k, Some("JWT+other"), &good_claims()).unwrap_err(),
            JoseError::InvalidClaim("typ")
        );
        assert_eq!(
            check(&k, Some("at+jwt"), &good_claims()).unwrap_err(),
            JoseError::InvalidClaim("typ")
        );
    }

    #[test]
    fn rejects_future_nbf_and_iat() {
        let k = rsa(Alg::RS256);
        let c = with(good_claims(), "nbf", json!(ts(120)));
        assert_eq!(
            check(&k, None, &c).unwrap_err(),
            JoseError::InvalidClaim("nbf")
        );
        let c = with(good_claims(), "iat", json!(ts(120)));
        assert_eq!(
            check(&k, None, &c).unwrap_err(),
            JoseError::InvalidClaim("iat")
        );
    }

    #[test]
    fn rejects_unregistered_key_and_unknown_kid() {
        let registered = rsa(Alg::RS256);
        let attacker = rsa(Alg::RS256);
        let t = attacker.signer.sign_jwt(None, &good_claims()).unwrap();
        assert_eq!(
            verify_client_assertion(&t, &jwks(&registered), &rules()).unwrap_err(),
            JoseError::UnknownKey
        );
        // Attacker reuses the registered kid: signature fails.
        let forged_signer = crate::keys::SigningKey::from_pkcs8(
            registered.jwk.kid.as_deref().unwrap(),
            Alg::RS256,
            &crate::keys::generate_rs256().unwrap().pkcs8,
        )
        .unwrap();
        let t = forged_signer.sign_jwt(None, &good_claims()).unwrap();
        assert_eq!(
            verify_client_assertion(&t, &jwks(&registered), &rules()).unwrap_err(),
            JoseError::BadSignature
        );
    }

    #[test]
    fn rejects_hs256_and_none() {
        let k = rsa(Alg::RS256);
        let t = crate::jws::test_keys::raw_token(
            &json!({"alg": "HS256", "kid": k.signer.kid()}),
            &good_claims(),
            b"mac",
        );
        assert!(matches!(
            verify_client_assertion(&t, &jwks(&k), &rules()),
            Err(JoseError::UnsupportedAlg(_))
        ));
        let t = crate::jws::test_keys::raw_token(&json!({"alg": "none"}), &good_claims(), b"");
        assert!(matches!(
            verify_client_assertion(&t, &jwks(&k), &rules()),
            Err(JoseError::UnsupportedAlg(_))
        ));
    }
}
