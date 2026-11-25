//! Strict compact-JWS parsing and signature verification against a JWK Set.
//!
//! Order: size cap → 3 segments → strict base64url → header JSON object → reject `crit` →
//! `alg` must be in the caller's allow-list (never `none`/HMAC: they are not representable) →
//! key by `kid` (or the single fitting key when `kid` is absent) → signature via jsonwebtoken →
//! claims JSON object. No claim validation happens here.

use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::JoseError;
use crate::encoding::b64url_decode;
use crate::jwk::{Jwk, Jwks};
use crate::keys::Alg;

/// Maximum accepted compact JWS size (bytes), checked before any decoding.
pub const MAX_JWS_LEN: usize = 16 * 1024;

/// The JOSE header members this crate looks at.
#[derive(Clone, Debug, Deserialize)]
pub struct JoseHeader {
    pub alg: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub typ: Option<String>,
    #[serde(default)]
    pub crit: Option<Vec<String>>,
}

/// A JWS whose signature verified. Claims are not validated.
#[derive(Clone, Debug)]
pub struct VerifiedJwt {
    pub header: JoseHeader,
    pub claims: Map<String, Value>,
}

struct Parts<'a> {
    header: JoseHeader,
    message: &'a str,
    payload_b64: &'a str,
    signature_b64: &'a str,
}

fn json_object(bytes: &[u8], what: &'static str) -> Result<Map<String, Value>, JoseError> {
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(JoseError::Malformed(what)),
    }
}

fn parse(token: &str) -> Result<Parts<'_>, JoseError> {
    if token.len() > MAX_JWS_LEN {
        return Err(JoseError::Malformed("JWS too large"));
    }
    let mut it = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(JoseError::Malformed("JWS must have exactly 3 segments"));
    };
    if h.is_empty() || p.is_empty() {
        return Err(JoseError::Malformed("empty JWS segment"));
    }
    let header_map = json_object(&b64url_decode(h)?, "JOSE header is not a JSON object")?;
    let header: JoseHeader = serde_json::from_value(Value::Object(header_map))
        .map_err(|_| JoseError::Malformed("invalid JOSE header"))?;
    let message = &token[..h.len() + 1 + p.len()];
    Ok(Parts {
        header,
        message,
        payload_b64: p,
        signature_b64: s,
    })
}

/// Parse the header of a compact JWS (structure checks only, no signature verification).
pub fn decode_header(token: &str) -> Result<JoseHeader, JoseError> {
    parse(token).map(|p| p.header)
}

/// Whether `jwk` can verify `alg`: matching kty (and P-256 for ES256), `use` absent or `sig`,
/// `alg` absent or equal.
fn fits(jwk: &Jwk, alg: Alg) -> bool {
    let kty_ok = match alg {
        Alg::RS256 | Alg::PS256 => jwk.kty == "RSA",
        Alg::ES256 => jwk.kty == "EC" && jwk.crv.as_deref() == Some("P-256"),
    };
    kty_ok
        && jwk.use_.as_deref().is_none_or(|u| u == "sig")
        && jwk.alg.as_deref().is_none_or(|a| a == alg.as_str())
}

fn select_key<'k>(keys: &'k Jwks, kid: Option<&str>, alg: Alg) -> Result<&'k Jwk, JoseError> {
    let mut candidates = keys
        .keys
        .iter()
        .filter(|k| match kid {
            Some(kid) => k.kid.as_deref() == Some(kid),
            None => true,
        })
        .filter(|k| fits(k, alg));
    match (candidates.next(), candidates.next()) {
        (Some(k), None) => Ok(k),
        _ => Err(JoseError::UnknownKey),
    }
}

fn decoding_key(jwk: &Jwk, alg: Alg) -> Result<DecodingKey, JoseError> {
    let bad = |_| JoseError::Malformed("invalid JWK key material");
    if alg.is_rsa() {
        let (Some(n), Some(e)) = (jwk.n.as_deref(), jwk.e.as_deref()) else {
            return Err(JoseError::Malformed("RSA JWK without n/e"));
        };
        // Strict decoding first: jsonwebtoken's own decoder is more lenient.
        b64url_decode(n)?;
        b64url_decode(e)?;
        DecodingKey::from_rsa_components(n, e).map_err(bad)
    } else {
        let (Some(x), Some(y)) = (jwk.x.as_deref(), jwk.y.as_deref()) else {
            return Err(JoseError::Malformed("EC JWK without x/y"));
        };
        if b64url_decode(x)?.len() != 32 || b64url_decode(y)?.len() != 32 {
            return Err(JoseError::Malformed("P-256 coordinates must be 32 bytes"));
        }
        DecodingKey::from_ec_components(x, y).map_err(bad)
    }
}

/// Verify a compact JWS against `keys`, allowing only the algorithms in `allowed`.
pub fn verify_jwt(token: &str, keys: &Jwks, allowed: &[Alg]) -> Result<VerifiedJwt, JoseError> {
    let parts = parse(token)?;
    if parts.header.crit.is_some() {
        return Err(JoseError::Malformed("crit header is not supported"));
    }
    let alg: Alg = parts.header.alg.parse()?;
    if !allowed.contains(&alg) {
        return Err(JoseError::unsupported_alg(&parts.header.alg));
    }
    let jwk = select_key(keys, parts.header.kid.as_deref(), alg)?;
    let key = decoding_key(jwk, alg)?;
    if parts.signature_b64.is_empty() {
        return Err(JoseError::BadSignature);
    }
    b64url_decode(parts.signature_b64).map_err(|_| JoseError::BadSignature)?;
    let ok = jsonwebtoken::crypto::verify(
        parts.signature_b64,
        parts.message.as_bytes(),
        &key,
        alg.to_jwt(),
    )
    .map_err(|_| JoseError::BadSignature)?;
    if !ok {
        return Err(JoseError::BadSignature);
    }
    let claims = json_object(
        &b64url_decode(parts.payload_b64)?,
        "JWT claims are not a JSON object",
    )?;
    Ok(VerifiedJwt {
        header: parts.header,
        claims,
    })
}

/// Test-only key helpers shared by the verification tests.
#[cfg(test)]
pub(crate) mod test_keys {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};

    use crate::encoding::b64url;
    use crate::jwk::{Jwk, thumbprint};
    use crate::keys::{Alg, SigningKey, generate_rs256};

    pub struct TestKey {
        pub signer: SigningKey,
        pub jwk: Jwk,
    }

    pub fn rsa(alg: Alg) -> TestKey {
        let g = generate_rs256().unwrap();
        let mut jwk = g.public_jwk.clone();
        jwk.alg = Some(alg.as_str().into());
        TestKey {
            signer: SigningKey::from_pkcs8(&g.kid, alg, &g.pkcs8).unwrap(),
            jwk,
        }
    }

    pub fn es256() -> TestKey {
        let ec = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let pkcs8 = ec.to_pkcs8v1().unwrap();
        let pt = ec.public_key().as_ref();
        let mut jwk = Jwk {
            kty: "EC".into(),
            kid: None,
            use_: Some("sig".into()),
            alg: Some("ES256".into()),
            n: None,
            e: None,
            crv: Some("P-256".into()),
            x: Some(b64url(&pt[1..33])),
            y: Some(b64url(&pt[33..65])),
        };
        let kid = thumbprint(&jwk).unwrap();
        jwk.kid = Some(kid.clone());
        TestKey {
            signer: SigningKey::from_pkcs8(&kid, Alg::ES256, pkcs8.as_ref()).unwrap(),
            jwk,
        }
    }

    /// Build an unsigned-by-us token from raw header/claims JSON plus an arbitrary signature.
    pub fn raw_token(header: &serde_json::Value, claims: &serde_json::Value, sig: &[u8]) -> String {
        format!(
            "{}.{}.{}",
            b64url(&serde_json::to_vec(header).unwrap()),
            b64url(&serde_json::to_vec(claims).unwrap()),
            b64url(sig)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::{es256, raw_token, rsa};
    use super::*;
    use crate::encoding::b64url;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::json;

    const ALL: &[Alg] = &[Alg::RS256, Alg::PS256, Alg::ES256];

    fn set(keys: &[&Jwk]) -> Jwks {
        Jwks {
            keys: keys.iter().map(|k| (*k).clone()).collect(),
        }
    }

    #[test]
    fn valid_rs256_ps256_es256_verify() {
        for k in [rsa(Alg::RS256), rsa(Alg::PS256), es256()] {
            let t = k
                .signer
                .sign_jwt(Some("JWT"), &json!({"sub": "a"}))
                .unwrap();
            let v = verify_jwt(&t, &set(&[&k.jwk]), ALL).unwrap();
            assert_eq!(v.claims["sub"], "a");
            assert_eq!(v.header.kid.as_deref(), Some(k.signer.kid()));
            assert_eq!(v.header.typ.as_deref(), Some("JWT"));
        }
    }

    #[test]
    fn float_claims_round_trip_exactly() {
        // Fuzz finding (jwt_decode): without serde_json's float_roundtrip feature, a large
        // integer literal parsed to f64 came back one ulp off after sign + verify.
        let raw = format!("{{\"x\": 24442{}}}", "2".repeat(48));
        let claims: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&raw).unwrap();
        let k = rsa(Alg::RS256);
        let t = k.signer.sign_jwt(None, &claims).unwrap();
        let v = verify_jwt(&t, &set(&[&k.jwk]), ALL).unwrap();
        assert_eq!(v.claims, claims);
    }

    #[test]
    fn hs256_alg_confusion_rejected() {
        // Classic confusion: HMAC with the RSA public key (modulus bytes) as the secret.
        let k = rsa(Alg::RS256);
        let secret = crate::encoding::b64url_decode(k.jwk.n.as_deref().unwrap()).unwrap();
        let mut h = Header::new(Algorithm::HS256);
        h.kid = Some(k.signer.kid().to_owned());
        let t = jsonwebtoken::encode(
            &h,
            &json!({"sub": "a"}),
            &EncodingKey::from_secret(&secret).unwrap(),
        )
        .unwrap();
        let err = verify_jwt(&t, &set(&[&k.jwk]), ALL).unwrap_err();
        assert!(matches!(err, JoseError::UnsupportedAlg(_)), "{err:?}");
    }

    #[test]
    fn alg_none_rejected() {
        let k = rsa(Alg::RS256);
        let t = raw_token(
            &json!({"alg": "none", "kid": k.signer.kid()}),
            &json!({"sub": "a"}),
            b"",
        );
        assert!(matches!(
            verify_jwt(&t, &set(&[&k.jwk]), ALL),
            Err(JoseError::UnsupportedAlg(_))
        ));
        // Trailing-dot form without signature segment content.
        let t2 = format!("{}.", t.trim_end_matches('.'));
        assert!(verify_jwt(&t2, &set(&[&k.jwk]), ALL).is_err());
    }

    #[test]
    fn alg_not_in_allow_list_rejected() {
        let k = es256();
        let t = k.signer.sign_jwt(None, &json!({"sub": "a"})).unwrap();
        assert!(matches!(
            verify_jwt(&t, &set(&[&k.jwk]), &[Alg::RS256]),
            Err(JoseError::UnsupportedAlg(_))
        ));
    }

    #[test]
    fn crit_rejected() {
        let k = rsa(Alg::RS256);
        let t = raw_token(
            &json!({"alg": "RS256", "kid": k.signer.kid(), "crit": ["exp"], "exp": 1}),
            &json!({"sub": "a"}),
            b"sig",
        );
        assert_eq!(
            verify_jwt(&t, &set(&[&k.jwk]), ALL).unwrap_err(),
            JoseError::Malformed("crit header is not supported")
        );
    }

    #[test]
    fn unknown_kid_rejected() {
        let k = rsa(Alg::RS256);
        let other = rsa(Alg::RS256);
        let t = k.signer.sign_jwt(None, &json!({"sub": "a"})).unwrap();
        assert_eq!(
            verify_jwt(&t, &set(&[&other.jwk]), ALL).unwrap_err(),
            JoseError::UnknownKey
        );
    }

    #[test]
    fn tampered_payload_rejected() {
        let k = rsa(Alg::RS256);
        let t = k.signer.sign_jwt(None, &json!({"sub": "a"})).unwrap();
        let parts: Vec<&str> = t.split('.').collect();
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            b64url(&serde_json::to_vec(&json!({"sub": "admin"})).unwrap()),
            parts[2]
        );
        assert_eq!(
            verify_jwt(&forged, &set(&[&k.jwk]), ALL).unwrap_err(),
            JoseError::BadSignature
        );
        let ek = es256();
        let t = ek.signer.sign_jwt(None, &json!({"sub": "a"})).unwrap();
        let mut bad = t.clone();
        bad.push_str("AA");
        assert!(verify_jwt(&bad, &set(&[&ek.jwk]), ALL).is_err());
    }

    #[test]
    fn missing_kid_selects_single_fitting_key() {
        let k = rsa(Alg::RS256);
        let ec = es256();
        // Re-sign with a header that has no kid.
        let t = k.signer.sign_jwt(None, &json!({"sub": "a"})).unwrap();
        let parts: Vec<&str> = t.split('.').collect();
        let no_kid_header = b64url(br#"{"alg":"RS256"}"#);
        let message = format!("{no_kid_header}.{}", parts[1]);
        let sig = k.signer.sign_message(&message).unwrap();
        let token = format!("{message}.{sig}");
        // One RSA key + one EC key: exactly one key fits RS256.
        assert!(verify_jwt(&token, &set(&[&k.jwk, &ec.jwk]), ALL).is_ok());
        // Two RSA keys fit: ambiguous.
        let k2 = rsa(Alg::RS256);
        assert_eq!(
            verify_jwt(&token, &set(&[&k.jwk, &k2.jwk]), ALL).unwrap_err(),
            JoseError::UnknownKey
        );
    }

    #[test]
    fn oversized_token_rejected() {
        let k = rsa(Alg::RS256);
        let big = "a".repeat(MAX_JWS_LEN);
        let t = k.signer.sign_jwt(None, &json!({"pad": big})).unwrap();
        assert_eq!(
            verify_jwt(&t, &set(&[&k.jwk]), ALL).unwrap_err(),
            JoseError::Malformed("JWS too large")
        );
    }

    #[test]
    fn structural_rejections() {
        let k = rsa(Alg::RS256);
        let keys = set(&[&k.jwk]);
        for bad in ["", "a.b", "a.b.c.d", "..", "e30.e30.", "!!.e30.AA"] {
            assert!(verify_jwt(bad, &keys, ALL).is_err(), "{bad:?} accepted");
        }
        // Header that is JSON but not an object.
        let t = format!("{}.e30.AA", b64url(b"[1]"));
        assert!(matches!(
            verify_jwt(&t, &keys, ALL),
            Err(JoseError::Malformed(_))
        ));
        // Claims that verify but are not an object.
        let message = format!(
            "{}.{}",
            b64url(format!(r#"{{"alg":"RS256","kid":"{}"}}"#, k.signer.kid()).as_bytes()),
            b64url(b"[1]")
        );
        let sig = k.signer.sign_message(&message).unwrap();
        assert!(matches!(
            verify_jwt(&format!("{message}.{sig}"), &keys, ALL),
            Err(JoseError::Malformed(_))
        ));
    }

    #[test]
    fn key_use_and_alg_constraints() {
        let k = rsa(Alg::RS256);
        let t = k.signer.sign_jwt(None, &json!({"sub": "a"})).unwrap();
        let mut enc = k.jwk.clone();
        enc.use_ = Some("enc".into());
        assert_eq!(
            verify_jwt(&t, &set(&[&enc]), ALL).unwrap_err(),
            JoseError::UnknownKey
        );
        let mut ps = k.jwk.clone();
        ps.alg = Some("PS256".into());
        assert_eq!(
            verify_jwt(&t, &set(&[&ps]), ALL).unwrap_err(),
            JoseError::UnknownKey
        );
    }

    #[test]
    fn decode_header_works() {
        let k = rsa(Alg::RS256);
        let t = k.signer.sign_jwt(Some("at+jwt"), &json!({})).unwrap();
        let h = decode_header(&t).unwrap();
        assert_eq!(h.alg, "RS256");
        assert_eq!(h.typ.as_deref(), Some("at+jwt"));
        assert!(decode_header("x").is_err());
    }
}
