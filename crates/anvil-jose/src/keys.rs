//! Signing-key generation and JWT signing (RS256, PS256, ES256, Ed25519).
//!
//! Keys are generated with aws-lc-rs and kept as PKCS#8. The JOSE header and JWK are built here;
//! jsonwebtoken (aws-lc-rs backend) only computes the signature (`jsonwebtoken::crypto::sign`).
//! RSA PKCS#8 is wrapped as a `PRIVATE KEY` PEM and loaded with `EncodingKey::from_rsa_pem`
//! (`from_rsa_der` expects PKCS#1 and would fail at sign time).
//!
//! Ed25519 uses the fully-specified JOSE name `Ed25519` (RFC 9864) in headers and JWKs. The
//! polymorphic `EdDSA` is neither emitted nor accepted (`"EdDSA".parse::<Alg>()` fails). jsonwebtoken
//! cannot express `Ed25519` in a header, which is fine: headers are serialised here and
//! jsonwebtoken only produces the signature bytes (`Algorithm::EdDSA` on an Ed25519 key).

use std::fmt;
use std::str::FromStr;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _,
};
use jsonwebtoken::{Algorithm, EncodingKey};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::JoseError;
use crate::encoding::b64url;
use crate::jwk::{Jwk, thumbprint};
use crate::pem::pkcs8_pem;

/// Asymmetric JWS algorithms AnvilID supports. `none` and HMAC algorithms do not exist here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Alg {
    RS256,
    PS256,
    ES256,
    /// Ed25519 signatures (RFC 9864 fully-specified name; never `EdDSA`).
    Ed25519,
}

impl Alg {
    /// The JOSE `alg` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Alg::RS256 => "RS256",
            Alg::PS256 => "PS256",
            Alg::ES256 => "ES256",
            Alg::Ed25519 => "Ed25519",
        }
    }

    /// The jsonwebtoken algorithm used for signature bytes only (Ed25519 → `EdDSA`). Never used
    /// to build or parse a header.
    pub(crate) fn to_jwt(self) -> Algorithm {
        match self {
            Alg::RS256 => Algorithm::RS256,
            Alg::PS256 => Algorithm::PS256,
            Alg::ES256 => Algorithm::ES256,
            Alg::Ed25519 => Algorithm::EdDSA,
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
            "Ed25519" => Ok(Alg::Ed25519),
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
    let jwk = Jwk {
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
    finish(Alg::RS256, jwk, pkcs8)
}

/// Generate a P-256 ES256 signing key. The JWK carries the 32-byte x/y halves of the
/// uncompressed public point.
pub fn generate_es256() -> Result<GeneratedKey, JoseError> {
    let kp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
        .map_err(|_| JoseError::Crypto("P-256 key generation failed"))?;
    let der = kp
        .to_pkcs8v1()
        .map_err(|_| JoseError::Crypto("PKCS#8 export failed"))?;
    let pkcs8 = Zeroizing::new(der.as_ref().to_vec());
    let pt = kp.public_key().as_ref();
    if pt.len() != 65 || pt[0] != 0x04 {
        return Err(JoseError::Crypto("unexpected P-256 public key encoding"));
    }
    let jwk = Jwk {
        kty: "EC".into(),
        kid: None,
        use_: Some("sig".into()),
        alg: Some(Alg::ES256.as_str().into()),
        n: None,
        e: None,
        crv: Some("P-256".into()),
        x: Some(b64url(&pt[1..33])),
        y: Some(b64url(&pt[33..65])),
    };
    finish(Alg::ES256, jwk, pkcs8)
}

/// Generate an Ed25519 signing key (`kty` `OKP`, `crv` `Ed25519`, `alg` `Ed25519`).
pub fn generate_ed25519() -> Result<GeneratedKey, JoseError> {
    let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| JoseError::Crypto("Ed25519 key generation failed"))?;
    let pkcs8 = Zeroizing::new(doc.as_ref().to_vec());
    let kp = Ed25519KeyPair::from_pkcs8(&pkcs8)
        .map_err(|_| JoseError::Crypto("Ed25519 key generation failed"))?;
    let jwk = Jwk {
        kty: "OKP".into(),
        kid: None,
        use_: Some("sig".into()),
        alg: Some(Alg::Ed25519.as_str().into()),
        n: None,
        e: None,
        crv: Some("Ed25519".into()),
        x: Some(b64url(kp.public_key().as_ref())),
        y: None,
    };
    finish(Alg::Ed25519, jwk, pkcs8)
}

/// Generate a signing key for `alg`. PS256 shares RS256 keys and is not a generation target.
pub fn generate(alg: Alg) -> Result<GeneratedKey, JoseError> {
    match alg {
        Alg::RS256 => generate_rs256(),
        Alg::ES256 => generate_es256(),
        Alg::Ed25519 => generate_ed25519(),
        Alg::PS256 => Err(JoseError::unsupported_alg(alg.as_str())),
    }
}

/// Set kid = RFC 7638 thumbprint on the JWK and assemble the key.
fn finish(alg: Alg, mut jwk: Jwk, pkcs8: Zeroizing<Vec<u8>>) -> Result<GeneratedKey, JoseError> {
    let kid = thumbprint(&jwk)?;
    jwk.kid = Some(kid.clone());
    Ok(GeneratedKey {
        kid,
        alg,
        public_jwk: jwk,
        pkcs8,
    })
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
        let key = match alg {
            Alg::RS256 | Alg::PS256 => {
                RsaKeyPair::from_pkcs8(pkcs8)
                    .map_err(|_| JoseError::Crypto("invalid RSA PKCS#8 key"))?;
                let pem = pkcs8_pem(pkcs8);
                EncodingKey::from_rsa_pem(pem.as_bytes())
                    .map_err(|_| JoseError::Crypto("invalid RSA PKCS#8 key"))?
            }
            Alg::ES256 => {
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
                    .map_err(|_| JoseError::Crypto("invalid P-256 PKCS#8 key"))?;
                EncodingKey::from_ec_der(pkcs8)
            }
            Alg::Ed25519 => {
                Ed25519KeyPair::from_pkcs8(pkcs8)
                    .map_err(|_| JoseError::Crypto("invalid Ed25519 PKCS#8 key"))?;
                EncodingKey::from_ed_der(pkcs8)
            }
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
    fn ed25519_name_only_never_eddsa() {
        assert_eq!(Alg::Ed25519.as_str(), "Ed25519");
        assert_eq!(Alg::Ed25519.to_string(), "Ed25519");
        assert_eq!("Ed25519".parse::<Alg>().unwrap(), Alg::Ed25519);
        assert!("EdDSA".parse::<Alg>().is_err());
        assert!("ed25519".parse::<Alg>().is_err());
    }

    #[test]
    fn generate_es256_jwk_shape() {
        let g = generate_es256().unwrap();
        let j = &g.public_jwk;
        assert_eq!(g.alg, Alg::ES256);
        assert_eq!(j.kty, "EC");
        assert_eq!(j.crv.as_deref(), Some("P-256"));
        assert_eq!(j.alg.as_deref(), Some("ES256"));
        assert_eq!(j.use_.as_deref(), Some("sig"));
        assert!(j.n.is_none() && j.e.is_none());
        assert_eq!(b64url_decode(j.x.as_deref().unwrap()).unwrap().len(), 32);
        assert_eq!(b64url_decode(j.y.as_deref().unwrap()).unwrap().len(), 32);
        assert_eq!(j.kid.as_deref(), Some(g.kid.as_str()));
        assert_eq!(g.kid, thumbprint(j).unwrap());
        // The PKCS#8 loads for signing and the signature verifies against the JWK.
        let key = SigningKey::from_pkcs8(&g.kid, Alg::ES256, &g.pkcs8).unwrap();
        let (h, _, message, sig) = split(&key.sign_jwt(None, &json!({"a": 1})).unwrap());
        assert_eq!(h["alg"], "ES256");
        let dk = DecodingKey::from_ec_components(j.x.as_deref().unwrap(), j.y.as_deref().unwrap())
            .unwrap();
        assert!(
            jsonwebtoken::crypto::verify(&sig, message.as_bytes(), &dk, Algorithm::ES256).unwrap()
        );
    }

    #[test]
    fn generate_ed25519_jwk_shape_and_header() {
        let g = generate_ed25519().unwrap();
        let j = &g.public_jwk;
        assert_eq!(g.alg, Alg::Ed25519);
        assert_eq!(j.kty, "OKP");
        assert_eq!(j.crv.as_deref(), Some("Ed25519"));
        assert_eq!(j.alg.as_deref(), Some("Ed25519"));
        assert_eq!(j.use_.as_deref(), Some("sig"));
        assert!(j.y.is_none() && j.n.is_none() && j.e.is_none());
        assert_eq!(b64url_decode(j.x.as_deref().unwrap()).unwrap().len(), 32);
        assert_eq!(g.kid, thumbprint(j).unwrap());
        assert_eq!(j.kid.as_deref(), Some(g.kid.as_str()));

        let key = SigningKey::from_pkcs8(&g.kid, Alg::Ed25519, &g.pkcs8).unwrap();
        let token = key.sign_jwt(Some("JWT"), &json!({"sub": "u"})).unwrap();
        let (h, _, message, sig) = split(&token);
        // Exactly these members, and never the polymorphic name.
        assert_eq!(h, json!({"alg": "Ed25519", "kid": g.kid, "typ": "JWT"}));
        assert!(!token.split('.').next().unwrap().is_empty());
        let dk = DecodingKey::from_ed_components(j.x.as_deref().unwrap()).unwrap();
        assert!(
            jsonwebtoken::crypto::verify(&sig, message.as_bytes(), &dk, Algorithm::EdDSA).unwrap()
        );
    }

    #[test]
    fn generate_dispatches_and_refuses_ps256() {
        assert_eq!(generate(Alg::RS256).unwrap().alg, Alg::RS256);
        assert_eq!(generate(Alg::ES256).unwrap().alg, Alg::ES256);
        assert_eq!(generate(Alg::Ed25519).unwrap().alg, Alg::Ed25519);
        assert!(matches!(
            generate(Alg::PS256),
            Err(JoseError::UnsupportedAlg(_))
        ));
    }

    #[test]
    fn from_pkcs8_rejects_cross_family_keys() {
        let ed = generate_ed25519().unwrap();
        let ec = generate_es256().unwrap();
        assert!(SigningKey::from_pkcs8("k", Alg::Ed25519, b"garbage").is_err());
        assert!(SigningKey::from_pkcs8("k", Alg::Ed25519, &ec.pkcs8).is_err());
        assert!(SigningKey::from_pkcs8("k", Alg::ES256, &ed.pkcs8).is_err());
        assert!(SigningKey::from_pkcs8("k", Alg::RS256, &ed.pkcs8).is_err());
    }

    #[test]
    fn debug_hides_material() {
        let g = generate_rs256().unwrap();
        let key = SigningKey::from_pkcs8(&g.kid, Alg::RS256, &g.pkcs8).unwrap();
        let dbg = format!("{key:?} {g:?}");
        assert!(dbg.contains(&g.kid));
        let pkcs8_b64 = crate::encoding::b64std(g.pkcs8.as_slice());
        assert!(!dbg.contains(&pkcs8_b64[..40]));
        assert!(!dbg.contains("pkcs8"));
        assert!(!dbg.contains("PRIVATE"));
    }
}
