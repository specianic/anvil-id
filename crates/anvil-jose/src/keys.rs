//! Signing-key generation and JWT signing.
//!
//! Keys are generated with aws-lc-rs and kept as PKCS#8. The JOSE header and JWK are built here;
//! jsonwebtoken (aws-lc-rs backend) only computes the signature (`jsonwebtoken::crypto::sign`).
//! RSA PKCS#8 is wrapped as a `PRIVATE KEY` PEM and loaded with `EncodingKey::from_rsa_pem`
//! (`from_rsa_der` expects PKCS#1 and would fail at sign time).

use std::fmt;
use std::str::FromStr;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jsonwebtoken::{Algorithm, EncodingKey};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::JoseError;
use crate::encoding::b64url;
use crate::jwk::{Jwk, thumbprint};

/// Asymmetric JWS algorithms AnvilID supports. `none` and HMAC algorithms do not exist here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Alg {
    RS256,
    PS256,
    ES256,
}

impl Alg {
    /// The JOSE `alg` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Alg::RS256 => "RS256",
            Alg::PS256 => "PS256",
            Alg::ES256 => "ES256",
        }
    }

    pub(crate) fn to_jwt(self) -> Algorithm {
        match self {
            Alg::RS256 => Algorithm::RS256,
            Alg::PS256 => Algorithm::PS256,
            Alg::ES256 => Algorithm::ES256,
        }
    }

    /// RSA family (RS256, PS256).
    #[must_use]
    pub fn is_rsa(self) -> bool {
        matches!(self, Alg::RS256 | Alg::PS256)
    }
}

impl fmt::Display for Alg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Alg {
    type Err = JoseError;

    /// Exact, case-sensitive match (RFC 7515: `alg` values are case-sensitive).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RS256" => Ok(Alg::RS256),
            "PS256" => Ok(Alg::PS256),
            "ES256" => Ok(Alg::ES256),
            other => Err(JoseError::unsupported_alg(other)),
        }
    }
}

/// A freshly generated key: the public JWK (kid = RFC 7638 thumbprint) and the PKCS#8 private key.
pub struct GeneratedKey {
    pub kid: String,
    pub alg: Alg,
    pub public_jwk: Jwk,
    pub pkcs8: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for GeneratedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedKey")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .field("public_jwk", &self.public_jwk)
            .finish_non_exhaustive()
    }
}

/// Generate an RSA-2048 RS256 signing key.
pub fn generate_rs256() -> Result<GeneratedKey, JoseError> {
    let kp = RsaKeyPair::generate(KeySize::Rsa2048)
        .map_err(|_| JoseError::Crypto("RSA key generation failed"))?;
    let der: Pkcs8V1Der<'static> = kp
        .as_der()
        .map_err(|_| JoseError::Crypto("PKCS#8 export failed"))?;
    let pkcs8 = Zeroizing::new(der.as_ref().to_vec());
    let public = kp.public_key();
    let mut jwk = Jwk {
        kty: "RSA".into(),
        kid: None,
        use_: Some("sig".into()),
        alg: Some(Alg::RS256.as_str().into()),
        n: Some(b64url(public.modulus().big_endian_without_leading_zero())),
        e: Some(b64url(public.exponent().big_endian_without_leading_zero())),
        crv: None,
        x: None,
        y: None,
    };
    let kid = thumbprint(&jwk)?;
    jwk.kid = Some(kid.clone());
    Ok(GeneratedKey {
        kid,
        alg: Alg::RS256,
        public_jwk: jwk,
        pkcs8,
    })
}

/// PKCS#8 DER as a `PRIVATE KEY` PEM with 64-column lines.
fn pkcs8_pem(pkcs8: &[u8]) -> Zeroizing<String> {
    let b64 = Zeroizing::new(STANDARD.encode(pkcs8));
    let mut pem = Zeroizing::new(String::with_capacity(b64.len() + b64.len() / 64 + 64));
    pem.push_str("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // base64 output is ASCII.
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

/// A loaded signing key. `Debug` shows only kid and alg.
pub struct SigningKey {
    kid: String,
    alg: Alg,
    key: EncodingKey,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    kid: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<&'a str>,
}

impl SigningKey {
    /// Load a PKCS#8 private key. The key is validated with aws-lc-rs first, so garbage input
    /// fails here rather than at sign time.
    pub fn from_pkcs8(kid: &str, alg: Alg, pkcs8: &[u8]) -> Result<Self, JoseError> {
        if kid.is_empty() {
            return Err(JoseError::Malformed("empty kid"));
        }
        let key = if alg.is_rsa() {
            RsaKeyPair::from_pkcs8(pkcs8)
                .map_err(|_| JoseError::Crypto("invalid RSA PKCS#8 key"))?;
            let pem = pkcs8_pem(pkcs8);
            EncodingKey::from_rsa_pem(pem.as_bytes())
                .map_err(|_| JoseError::Crypto("invalid RSA PKCS#8 key"))?
        } else {
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
                .map_err(|_| JoseError::Crypto("invalid P-256 PKCS#8 key"))?;
            EncodingKey::from_ec_der(pkcs8)
        };
        Ok(Self {
            kid: kid.to_owned(),
            alg,
            key,
        })
    }

    /// The key id placed in every JWS header.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The signing algorithm.
    #[must_use]
    pub fn alg(&self) -> Alg {
        self.alg
    }

    /// Sign `claims` (must serialise to a JSON object) as a compact JWS with header
    /// `{"alg","kid","typ"?}`.
    pub fn sign_jwt<C: Serialize>(
        &self,
        typ: Option<&str>,
        claims: &C,
    ) -> Result<String, JoseError> {
        let header = serde_json::to_vec(&Header {
            alg: self.alg.as_str(),
            kid: &self.kid,
            typ,
        })
        .map_err(|_| JoseError::Malformed("header serialisation failed"))?;
        let claims = serde_json::to_value(claims)
            .map_err(|_| JoseError::Malformed("claims serialisation failed"))?;
        if !claims.is_object() {
            return Err(JoseError::Malformed("claims must be a JSON object"));
        }
        let claims = serde_json::to_vec(&claims)
            .map_err(|_| JoseError::Malformed("claims serialisation failed"))?;
        let message = format!("{}.{}", b64url(&header), b64url(&claims));
        let sig = self.sign_message(&message)?;
        Ok(format!("{message}.{sig}"))
    }

    /// Base64url signature over an already-encoded `header.payload` signing input.
    pub(crate) fn sign_message(&self, message: &str) -> Result<String, JoseError> {
        jsonwebtoken::crypto::sign(message.as_bytes(), &self.key, self.alg.to_jwt())
            .map_err(|_| JoseError::Crypto("signing failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::b64url_decode;
    use jsonwebtoken::DecodingKey;
    use serde_json::{Value, json};

    fn split(token: &str) -> (Value, Value, String, String) {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let h = serde_json::from_slice(&b64url_decode(parts[0]).unwrap()).unwrap();
        let c = serde_json::from_slice(&b64url_decode(parts[1]).unwrap()).unwrap();
        (
            h,
            c,
            format!("{}.{}", parts[0], parts[1]),
            parts[2].to_owned(),
        )
    }

    #[test]
    fn generate_sign_and_verify_rs256() {
        let g = generate_rs256().unwrap();
        assert_eq!(g.kid, thumbprint(&g.public_jwk).unwrap());
        assert_eq!(g.public_jwk.kid.as_deref(), Some(g.kid.as_str()));
        assert_eq!(g.public_jwk.use_.as_deref(), Some("sig"));
        assert_eq!(g.public_jwk.alg.as_deref(), Some("RS256"));
        assert_eq!(g.public_jwk.e.as_deref(), Some("AQAB"));
        // 2048-bit modulus: 256 bytes -> 342 base64url chars.
        assert_eq!(g.public_jwk.n.as_ref().unwrap().len(), 342);

        let key = SigningKey::from_pkcs8(&g.kid, Alg::RS256, &g.pkcs8).unwrap();
        assert_eq!(key.kid(), g.kid);
        let token = key
            .sign_jwt(Some("at+jwt"), &json!({"sub": "u1", "iss": "https://op"}))
            .unwrap();
        let (h, c, message, sig) = split(&token);
        assert_eq!(h, json!({"alg": "RS256", "kid": g.kid, "typ": "at+jwt"}));
        assert_eq!(c["sub"], "u1");

        let dk = DecodingKey::from_rsa_components(
            g.public_jwk.n.as_deref().unwrap(),
            g.public_jwk.e.as_deref().unwrap(),
        )
        .unwrap();
        assert!(
            jsonwebtoken::crypto::verify(&sig, message.as_bytes(), &dk, Algorithm::RS256).unwrap()
        );
        // A different message does not verify with that signature.
        assert!(!jsonwebtoken::crypto::verify(&sig, b"x.y", &dk, Algorithm::RS256).unwrap());
    }

    #[test]
    fn header_without_typ() {
        let g = generate_rs256().unwrap();
        let key = SigningKey::from_pkcs8(&g.kid, Alg::RS256, &g.pkcs8).unwrap();
        let token = key.sign_jwt(None, &json!({"a": 1})).unwrap();
        let (h, ..) = split(&token);
        assert_eq!(h, json!({"alg": "RS256", "kid": g.kid}));
    }

    #[test]
    fn non_object_claims_rejected() {
        let g = generate_rs256().unwrap();
        let key = SigningKey::from_pkcs8(&g.kid, Alg::RS256, &g.pkcs8).unwrap();
        assert!(key.sign_jwt(None, &json!([1, 2])).is_err());
        assert!(key.sign_jwt(None, &"str").is_err());
    }

    #[test]
    fn from_pkcs8_rejects_garbage() {
        assert!(SigningKey::from_pkcs8("k", Alg::RS256, b"garbage").is_err());
        assert!(SigningKey::from_pkcs8("k", Alg::RS256, &[]).is_err());
        assert!(SigningKey::from_pkcs8("k", Alg::ES256, b"garbage").is_err());
        let g = generate_rs256().unwrap();
        assert!(SigningKey::from_pkcs8("", Alg::RS256, &g.pkcs8).is_err());
        // An RSA key cannot be loaded as ES256.
        assert!(SigningKey::from_pkcs8("k", Alg::ES256, &g.pkcs8).is_err());
    }

    #[test]
    fn es256_and_ps256_sign() {
        let ec = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let pkcs8 = ec.to_pkcs8v1().unwrap();
        let key = SigningKey::from_pkcs8("ec1", Alg::ES256, pkcs8.as_ref()).unwrap();
        let token = key.sign_jwt(None, &json!({"a": 1})).unwrap();
        let (h, _, message, sig) = split(&token);
        assert_eq!(h["alg"], "ES256");
        let pt = ec.public_key().as_ref();
        let dk =
            DecodingKey::from_ec_components(&b64url(&pt[1..33]), &b64url(&pt[33..65])).unwrap();
        assert!(
            jsonwebtoken::crypto::verify(&sig, message.as_bytes(), &dk, Algorithm::ES256).unwrap()
        );

        let g = generate_rs256().unwrap();
        let ps = SigningKey::from_pkcs8(&g.kid, Alg::PS256, &g.pkcs8).unwrap();
        let token = ps.sign_jwt(None, &json!({"a": 1})).unwrap();
        let (h, ..) = split(&token);
        assert_eq!(h["alg"], "PS256");
    }

    #[test]
    fn alg_parse() {
        assert_eq!("RS256".parse::<Alg>().unwrap(), Alg::RS256);
        assert_eq!("ES256".parse::<Alg>().unwrap(), Alg::ES256);
        assert!("rs256".parse::<Alg>().is_err());
        assert!("none".parse::<Alg>().is_err());
        assert!("HS256".parse::<Alg>().is_err());
    }

    #[test]
    fn debug_hides_material() {
        let g = generate_rs256().unwrap();
        let key = SigningKey::from_pkcs8(&g.kid, Alg::RS256, &g.pkcs8).unwrap();
        let dbg = format!("{key:?} {g:?}");
        assert!(dbg.contains(&g.kid));
        let pkcs8_b64 = STANDARD.encode(g.pkcs8.as_slice());
        assert!(!dbg.contains(&pkcs8_b64[..40]));
        assert!(!dbg.contains("pkcs8"));
        assert!(!dbg.contains("PRIVATE"));
    }
}
