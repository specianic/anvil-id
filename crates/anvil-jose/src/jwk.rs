//! Public JWKs, JWK Sets and RFC 7638 thumbprints, built by this crate (ARCHITECTURE.md §8.1).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::JoseError;
use crate::encoding::{b64url, sha256};

/// Members that only appear in private (or symmetric) JWKs. A public JWK Set must not carry them.
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// A public JSON Web Key (RFC 7517). Unknown members are ignored on input.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// A JWK Set (RFC 7517 §5).
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

fn required<'a>(v: &'a Option<String>, what: &'static str) -> Result<&'a str, JoseError> {
    v.as_deref().ok_or(JoseError::Malformed(what))
}

fn json_str(s: &str) -> String {
    // Serialising a &str cannot fail.
    serde_json::to_string(s).unwrap_or_default()
}

/// RFC 7638 SHA-256 thumbprint, base64url. RSA uses `{"e","kty","n"}`, EC uses
/// `{"crv","kty","x","y"}`, members in lexicographic order with no whitespace.
pub fn thumbprint(jwk: &Jwk) -> Result<String, JoseError> {
    let canonical = match jwk.kty.as_str() {
        "RSA" => format!(
            r#"{{"e":{},"kty":"RSA","n":{}}}"#,
            json_str(required(&jwk.e, "RSA JWK without e")?),
            json_str(required(&jwk.n, "RSA JWK without n")?),
        ),
        "EC" => format!(
            r#"{{"crv":{},"kty":"EC","x":{},"y":{}}}"#,
            json_str(required(&jwk.crv, "EC JWK without crv")?),
            json_str(required(&jwk.x, "EC JWK without x")?),
            json_str(required(&jwk.y, "EC JWK without y")?),
        ),
        _ => return Err(JoseError::Malformed("unsupported kty")),
    };
    Ok(b64url(&sha256(canonical.as_bytes())))
}

fn check_public(obj: &Value) -> Result<(), JoseError> {
    let map = obj
        .as_object()
        .ok_or(JoseError::Malformed("JWK is not a JSON object"))?;
    if PRIVATE_MEMBERS.iter().any(|m| map.contains_key(*m)) {
        return Err(JoseError::Malformed("JWK contains private key material"));
    }
    Ok(())
}

fn jwk_from_value(v: Value) -> Result<Jwk, JoseError> {
    check_public(&v)?;
    serde_json::from_value(v).map_err(|_| JoseError::Malformed("invalid JWK"))
}

impl Jwks {
    /// Parse a JWK Set document. Rejects any key carrying private members (`d`, `p`, `q`, ...).
    pub fn parse(json: &str) -> Result<Self, JoseError> {
        let v: Value =
            serde_json::from_str(json).map_err(|_| JoseError::Malformed("JWKS is not JSON"))?;
        let keys = v
            .as_object()
            .and_then(|o| o.get("keys"))
            .and_then(Value::as_array)
            .ok_or(JoseError::Malformed("JWKS without keys array"))?;
        let keys = keys
            .iter()
            .cloned()
            .map(jwk_from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { keys })
    }

    /// Build a set from individual public JWK JSON documents (one per stored signing key).
    pub fn from_public_jwks<'a>(
        jwks: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, JoseError> {
        let keys = jwks
            .into_iter()
            .map(|s| {
                let v: Value =
                    serde_json::from_str(s).map_err(|_| JoseError::Malformed("JWK is not JSON"))?;
                jwk_from_value(v)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { keys })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7638 §3.1 example key.
    const RFC7638_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    fn rfc7638_key() -> Jwk {
        Jwk {
            kty: "RSA".into(),
            kid: Some("2011-04-29".into()),
            use_: None,
            alg: Some("RS256".into()),
            n: Some(RFC7638_N.into()),
            e: Some("AQAB".into()),
            crv: None,
            x: None,
            y: None,
        }
    }

    #[test]
    fn rfc7638_thumbprint_vector() {
        assert_eq!(
            thumbprint(&rfc7638_key()).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn thumbprint_requires_members() {
        let mut k = rfc7638_key();
        k.e = None;
        assert!(thumbprint(&k).is_err());
        let ec = Jwk {
            kty: "EC".into(),
            kid: None,
            use_: None,
            alg: None,
            n: None,
            e: None,
            crv: Some("P-256".into()),
            x: Some("x".into()),
            y: None,
        };
        assert!(thumbprint(&ec).is_err());
        let oct = Jwk {
            kty: "oct".into(),
            ..rfc7638_key()
        };
        assert!(thumbprint(&oct).is_err());
    }

    #[test]
    fn serialisation_skips_none_and_renames_use() {
        let mut k = rfc7638_key();
        k.use_ = Some("sig".into());
        let s = serde_json::to_string(&k).unwrap();
        assert!(s.contains(r#""use":"sig""#));
        assert!(!s.contains("crv") && !s.contains("null"));
    }

    #[test]
    fn parse_rejects_private_members() {
        for m in PRIVATE_MEMBERS {
            let doc = format!(r#"{{"keys":[{{"kty":"RSA","n":"AQ","e":"AQAB","{m}":"AQ"}}]}}"#);
            assert!(Jwks::parse(&doc).is_err(), "member {m} accepted");
            let single = format!(r#"{{"kty":"RSA","n":"AQ","e":"AQAB","{m}":"AQ"}}"#);
            assert!(Jwks::from_public_jwks([single.as_str()]).is_err());
        }
    }

    #[test]
    fn parse_accepts_public_set_and_ignores_unknown_members() {
        let doc = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"a","n":"{RFC7638_N}","e":"AQAB","x5t":"zz"}},{{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}}]}}"#
        );
        let set = Jwks::parse(&doc).unwrap();
        assert_eq!(set.keys.len(), 2);
        assert_eq!(set.keys[0].kid.as_deref(), Some("a"));
        assert!(Jwks::parse("[]").is_err());
        assert!(Jwks::parse(r#"{"keys":{}}"#).is_err());
        assert!(Jwks::parse("not json").is_err());
    }

    #[test]
    fn from_public_jwks_roundtrip() {
        let k = rfc7638_key();
        let s = serde_json::to_string(&k).unwrap();
        let set = Jwks::from_public_jwks([s.as_str(), s.as_str()]).unwrap();
        assert_eq!(set.keys, vec![k.clone(), k]);
    }
}
