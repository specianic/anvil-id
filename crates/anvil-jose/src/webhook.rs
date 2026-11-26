//! Standard Webhooks v1 signatures and signing secrets (ADM-05).
//!
//! - Signature: `v1,` + base64(HMAC-SHA256(key, "{msg_id}.{timestamp}.{body}")), sent in the
//!   `webhook-signature` header next to `webhook-id` and `webhook-timestamp`.
//! - Secret: `whsec_` + base64 of the key bytes. The HMAC key is the decoded part, never the
//!   string itself. AnvilID generates 32-byte keys; the spec allows 24 to 64 bytes.
//!
//! The workspace's single HMAC-SHA-256 ([`crate::hmac_sha256`]) and single base64
//! implementation ([`crate::encoding`]).

use zeroize::Zeroizing;

use crate::JoseError;
use crate::encoding::{b64std, b64std_decode, random_bytes};
use crate::hmac::hmac_sha256;

/// Prefix of a Standard Webhooks signing secret.
pub const WEBHOOK_SECRET_PREFIX: &str = "whsec_";

/// Bytes of a generated signing key.
pub const WEBHOOK_SECRET_BYTES: usize = 32;

/// Smallest key length accepted by [`parse_webhook_secret`] (Standard Webhooks: 24 bytes).
pub const WEBHOOK_SECRET_MIN_BYTES: usize = 24;

/// Largest key length accepted by [`parse_webhook_secret`] (Standard Webhooks: 64 bytes).
pub const WEBHOOK_SECRET_MAX_BYTES: usize = 64;

/// The `v1` signature of one message: `v1,<base64(HMAC-SHA256(secret, "{msg_id}.{ts}.{body}"))>`.
///
/// `secret` is the decoded key ([`parse_webhook_secret`]), `ts` the `webhook-timestamp` value in
/// unix seconds and `body` the exact bytes sent.
#[must_use]
pub fn signature_v1(secret: &[u8], msg_id: &str, ts: i64, body: &[u8]) -> String {
    let ts = ts.to_string();
    let tag = hmac_sha256(
        secret,
        &[msg_id.as_bytes(), b".", ts.as_bytes(), b".", body],
    );
    format!("v1,{}", b64std(&tag))
}

/// A new signing secret: `whsec_` + base64 of [`WEBHOOK_SECRET_BYTES`] random bytes. Shown to
/// the operator once; only the sealed form is stored.
#[must_use]
pub fn generate_webhook_secret() -> Zeroizing<String> {
    let key = Zeroizing::new(random_bytes::<WEBHOOK_SECRET_BYTES>());
    let encoded = Zeroizing::new(b64std(key.as_ref()));
    let mut out = Zeroizing::new(String::with_capacity(
        WEBHOOK_SECRET_PREFIX.len() + encoded.len(),
    ));
    out.push_str(WEBHOOK_SECRET_PREFIX);
    out.push_str(&encoded);
    out
}

/// The HMAC key of a `whsec_` secret. Rejects a missing prefix, invalid (non-canonical) base64
/// and keys outside 24 to 64 bytes.
pub fn parse_webhook_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>, JoseError> {
    let encoded = secret
        .strip_prefix(WEBHOOK_SECRET_PREFIX)
        .ok_or(JoseError::Malformed(
            "webhook secret must start with whsec_",
        ))?;
    let key = Zeroizing::new(b64std_decode(encoded)?);
    if !(WEBHOOK_SECRET_MIN_BYTES..=WEBHOOK_SECRET_MAX_BYTES).contains(&key.len()) {
        return Err(JoseError::Malformed(
            "webhook secret must decode to 24 to 64 bytes",
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The example published in the Standard Webhooks specification (spec/standard-webhooks.md,
    // "Signature scheme"), with its 24-byte example secret.
    const SPEC_SECRET: &str = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    const SPEC_MSG_ID: &str = "msg_p5jXN8AQM9LWM0D4loKWxJek";
    const SPEC_TS: i64 = 1_614_265_330;
    const SPEC_BODY: &[u8] = br#"{"test": 2432232314}"#;
    const SPEC_SIGNATURE: &str = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";

    #[test]
    fn signature_matches_spec_test_vector() {
        let key = parse_webhook_secret(SPEC_SECRET).unwrap();
        assert_eq!(
            signature_v1(&key, SPEC_MSG_ID, SPEC_TS, SPEC_BODY),
            SPEC_SIGNATURE
        );
    }

    #[test]
    fn signature_changes_with_every_input() {
        let key = parse_webhook_secret(SPEC_SECRET).unwrap();
        let base = signature_v1(&key, SPEC_MSG_ID, SPEC_TS, SPEC_BODY);
        assert_ne!(
            signature_v1(&key, SPEC_MSG_ID, SPEC_TS, br#"{"test": 2432232315}"#),
            base
        );
        assert_ne!(
            signature_v1(&key, SPEC_MSG_ID, SPEC_TS + 1, SPEC_BODY),
            base
        );
        assert_ne!(
            signature_v1(&key, "msg_p5jXN8AQM9LWM0D4loKWxJel", SPEC_TS, SPEC_BODY),
            base
        );
        let other = parse_webhook_secret(&generate_webhook_secret()).unwrap();
        assert_ne!(signature_v1(&other, SPEC_MSG_ID, SPEC_TS, SPEC_BODY), base);
    }

    #[test]
    fn signature_uses_the_decoded_key_not_the_string() {
        let wrong = signature_v1(SPEC_SECRET.as_bytes(), SPEC_MSG_ID, SPEC_TS, SPEC_BODY);
        assert_ne!(wrong, SPEC_SIGNATURE);
    }

    #[test]
    fn generated_secret_shape() {
        let a = generate_webhook_secret();
        let b = generate_webhook_secret();
        assert!(a.starts_with("whsec_"));
        assert_ne!(*a, *b);
        let key = parse_webhook_secret(&a).unwrap();
        assert_eq!(key.len(), WEBHOOK_SECRET_BYTES);
        assert_eq!(
            b64std_decode(a.strip_prefix("whsec_").unwrap())
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn parse_rejects_bad_secrets() {
        let good = generate_webhook_secret();
        let body = good.strip_prefix("whsec_").unwrap();
        for bad in [
            // wrong or missing prefix
            body.to_owned(),
            format!("whsec{body}"),
            format!("WHSEC_{body}"),
            format!("sk_{body}"),
            // bad base64: URL alphabet, whitespace, garbage, empty
            format!("whsec_{}", body.replace('+', "-").replace('/', "_") + "-_"),
            format!("whsec_ {body}"),
            "whsec_!!!!".to_owned(),
            "whsec_".to_owned(),
            // too short (16 bytes) and too long (65 bytes)
            format!("whsec_{}", b64std(&[7u8; 16])),
            format!("whsec_{}", b64std(&[7u8; 65])),
        ] {
            assert!(parse_webhook_secret(&bad).is_err(), "{bad:?}");
        }
        assert!(parse_webhook_secret(&format!("whsec_{}", b64std(&[7u8; 24]))).is_ok());
        assert!(parse_webhook_secret(&format!("whsec_{}", b64std(&[7u8; 64]))).is_ok());
    }
}
