//! Verification of tokens this OP issued (access tokens, `id_token_hint`).
//!
//! The caller passes the published key set: a retired key that is still published still verifies,
//! and the caller decides which keys are published.

use time::OffsetDateTime;

use crate::JoseError;
use crate::client_assertion::numeric_date;
use crate::jwk::Jwks;
use crate::jws::{VerifiedJwt, verify_jwt};
use crate::keys::Alg;

/// Whether `exp` is enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryCheck {
    /// Access tokens: `exp` is required and must be in the future.
    Enforce,
    /// `id_token_hint`: expired hints are allowed (OIDC Core §3.1.2.1).
    Ignore,
}

fn typ_matches(actual: &str, expected: &str) -> bool {
    // RFC 7515 §4.1.9: an "application/" prefix may be omitted; media types are case-insensitive.
    let strip = |s: &str| {
        if s.len() > 12 && s[..12].eq_ignore_ascii_case("application/") {
            s[12..].to_owned()
        } else {
            s.to_owned()
        }
    };
    strip(actual).eq_ignore_ascii_case(&strip(expected))
}

/// Verify an OP-issued token: RS256 only, signed by a published key, `iss` exactly `issuer`,
/// `typ` equal to `expected_typ` when given, `exp` per `expiry`.
pub fn verify_op_token(
    token: &str,
    published: &Jwks,
    issuer: &str,
    expected_typ: Option<&str>,
    expiry: ExpiryCheck,
    now: OffsetDateTime,
) -> Result<VerifiedJwt, JoseError> {
    verify_op_token_algs(
        token,
        published,
        &[Alg::RS256],
        issuer,
        expected_typ,
        expiry,
        now,
    )
}

/// [`verify_op_token`] with an explicit algorithm allow-list (e.g. RS256, ES256 and Ed25519 once
/// tenants sign with more than one algorithm). The allow-list is checked before any crypto.
pub fn verify_op_token_algs(
    token: &str,
    published: &Jwks,
    allowed: &[Alg],
    issuer: &str,
    expected_typ: Option<&str>,
    expiry: ExpiryCheck,
    now: OffsetDateTime,
) -> Result<VerifiedJwt, JoseError> {
    let jwt = verify_jwt(token, published, allowed)?;
    if let Some(expected) = expected_typ {
        match jwt.header.typ.as_deref() {
            Some(actual) if typ_matches(actual, expected) => {}
            _ => return Err(JoseError::InvalidClaim("typ")),
        }
    }
    if jwt.claims.get("iss").and_then(|v| v.as_str()) != Some(issuer) {
        return Err(JoseError::InvalidClaim("iss"));
    }
    if expiry == ExpiryCheck::Enforce {
        let exp = numeric_date(&jwt.claims, "exp", "exp")?.ok_or(JoseError::InvalidClaim("exp"))?;
        if exp <= now {
            return Err(JoseError::Expired);
        }
    }
    Ok(jwt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::test_keys::{TestKey, ed25519, es256, rsa};
    use serde_json::{Value, json};

    const ISSUER: &str = "https://op.example.test";

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn claims(exp_offset: i64) -> Value {
        json!({"iss": ISSUER, "sub": "u1", "exp": now().unix_timestamp() + exp_offset})
    }

    fn published(keys: &[&TestKey]) -> Jwks {
        Jwks {
            keys: keys.iter().map(|k| k.jwk.clone()).collect(),
        }
    }

    #[test]
    fn valid_access_token() {
        let k = rsa(Alg::RS256);
        let t = k.signer.sign_jwt(Some("at+jwt"), &claims(60)).unwrap();
        let v = verify_op_token(
            &t,
            &published(&[&k]),
            ISSUER,
            Some("at+jwt"),
            ExpiryCheck::Enforce,
            now(),
        )
        .unwrap();
        assert_eq!(v.claims["sub"], "u1");
        let t = k
            .signer
            .sign_jwt(Some("application/AT+JWT"), &claims(60))
            .unwrap();
        assert!(
            verify_op_token(
                &t,
                &published(&[&k]),
                ISSUER,
                Some("at+jwt"),
                ExpiryCheck::Enforce,
                now()
            )
            .is_ok()
        );
    }

    #[test]
    fn wrong_issuer_rejected() {
        let k = rsa(Alg::RS256);
        let mut c = claims(60);
        c["iss"] = json!("https://op.example.test/");
        let t = k.signer.sign_jwt(Some("at+jwt"), &c).unwrap();
        assert_eq!(
            verify_op_token(
                &t,
                &published(&[&k]),
                ISSUER,
                Some("at+jwt"),
                ExpiryCheck::Enforce,
                now()
            )
            .unwrap_err(),
            JoseError::InvalidClaim("iss")
        );
    }

    #[test]
    fn wrong_or_missing_typ_rejected() {
        let k = rsa(Alg::RS256);
        for typ in [Some("JWT"), None] {
            let t = k.signer.sign_jwt(typ, &claims(60)).unwrap();
            assert_eq!(
                verify_op_token(
                    &t,
                    &published(&[&k]),
                    ISSUER,
                    Some("at+jwt"),
                    ExpiryCheck::Enforce,
                    now()
                )
                .unwrap_err(),
                JoseError::InvalidClaim("typ")
            );
        }
    }

    #[test]
    fn expiry_enforced_for_access_tokens_only() {
        let k = rsa(Alg::RS256);
        let t = k.signer.sign_jwt(Some("at+jwt"), &claims(-1)).unwrap();
        assert_eq!(
            verify_op_token(
                &t,
                &published(&[&k]),
                ISSUER,
                Some("at+jwt"),
                ExpiryCheck::Enforce,
                now()
            )
            .unwrap_err(),
            JoseError::Expired
        );
        let hint = k.signer.sign_jwt(Some("JWT"), &claims(-3600)).unwrap();
        assert!(
            verify_op_token(
                &hint,
                &published(&[&k]),
                ISSUER,
                None,
                ExpiryCheck::Ignore,
                now()
            )
            .is_ok()
        );
        let mut no_exp = claims(0);
        no_exp.as_object_mut().unwrap().remove("exp");
        let t = k.signer.sign_jwt(Some("at+jwt"), &no_exp).unwrap();
        assert_eq!(
            verify_op_token(
                &t,
                &published(&[&k]),
                ISSUER,
                Some("at+jwt"),
                ExpiryCheck::Enforce,
                now()
            )
            .unwrap_err(),
            JoseError::InvalidClaim("exp")
        );
    }

    #[test]
    fn unpublished_key_rejected_retired_published_key_accepted() {
        let current = rsa(Alg::RS256);
        let retired = rsa(Alg::RS256);
        let stranger = rsa(Alg::RS256);
        let set = published(&[&current, &retired]);
        let t = stranger
            .signer
            .sign_jwt(Some("at+jwt"), &claims(60))
            .unwrap();
        assert_eq!(
            verify_op_token(
                &t,
                &set,
                ISSUER,
                Some("at+jwt"),
                ExpiryCheck::Enforce,
                now()
            )
            .unwrap_err(),
            JoseError::UnknownKey
        );
        let t = retired
            .signer
            .sign_jwt(Some("at+jwt"), &claims(60))
            .unwrap();
        assert!(
            verify_op_token(
                &t,
                &set,
                ISSUER,
                Some("at+jwt"),
                ExpiryCheck::Enforce,
                now()
            )
            .is_ok()
        );
    }

    #[test]
    fn explicit_allow_list_accepts_ed25519_and_es256_only_when_listed() {
        let all = [Alg::RS256, Alg::ES256, Alg::Ed25519];
        for k in [rsa(Alg::RS256), es256(), ed25519()] {
            let t = k.signer.sign_jwt(Some("at+jwt"), &claims(60)).unwrap();
            let ok = verify_op_token_algs(
                &t,
                &published(&[&k]),
                &all,
                ISSUER,
                Some("at+jwt"),
                ExpiryCheck::Enforce,
                now(),
            );
            assert!(ok.is_ok(), "{:?}", k.signer.alg());
            let refused = verify_op_token_algs(
                &t,
                &published(&[&k]),
                &[],
                ISSUER,
                Some("at+jwt"),
                ExpiryCheck::Enforce,
                now(),
            );
            assert!(matches!(refused, Err(JoseError::UnsupportedAlg(_))));
        }
    }

    #[test]
    fn only_rs256_accepted() {
        let k = es256();
        let t = k.signer.sign_jwt(Some("at+jwt"), &claims(60)).unwrap();
        assert!(matches!(
            verify_op_token(
                &t,
                &published(&[&k]),
                ISSUER,
                Some("at+jwt"),
                ExpiryCheck::Enforce,
                now()
            ),
            Err(JoseError::UnsupportedAlg(_))
        ));
    }
}
