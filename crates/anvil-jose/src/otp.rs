//! TOTP (RFC 6238) for authenticator apps: secret generation, `otpauth://` URIs and code checks.
//!
//! A thin wrapper over totp-rs with the parameters every authenticator app supports: HMAC-SHA1,
//! 6 digits, 30 s steps, ±1 step skew. totp-rs does the HOTP math and compares tokens in constant
//! time. Secrets come from the aws-lc-rs CSPRNG (totp-rs `gen_secret` is not enabled).
//!
//! Single use is NOT enforced here: [`check_code`] returns the matched time step and the caller
//! must atomically record it (storage compare-and-set on the credential counter) so a code is
//! accepted at most once (RFC 6238 §5.2).

use std::fmt;

use totp_rs::{Algorithm, Builder, Secret, Totp};
use zeroize::Zeroizing;

use crate::JoseError;
use crate::encoding::random_bytes;

/// Generated secret length: 160 bits (RFC 4226 §4 recommendation).
pub const TOTP_SECRET_LEN: usize = 20;
const MIN_SECRET_LEN: usize = 16;
const MAX_SECRET_LEN: usize = 64;
const DIGITS: u8 = 6;
const STEP_SECS: u64 = 30;
const SKEW_STEPS: u16 = 1;

/// A TOTP shared secret. Zeroized on drop; `Debug` never prints it.
pub struct TotpSecret {
    bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSecret(..)")
    }
}

impl TotpSecret {
    /// 20 fresh random bytes from the aws-lc-rs system RNG.
    #[must_use]
    pub fn generate() -> Self {
        let raw = Zeroizing::new(random_bytes::<TOTP_SECRET_LEN>());
        Self {
            bytes: Zeroizing::new(raw.to_vec()),
        }
    }

    /// From stored bytes (e.g. a seed opened with the KEK). 16..=64 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, JoseError> {
        if !(MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&bytes.len()) {
            return Err(JoseError::Crypto("TOTP secret must be 16 to 64 bytes"));
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes.to_vec()),
        })
    }

    /// The raw secret, for sealing with the KEK.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// RFC 4648 base32 without padding, for manual entry in an authenticator app.
    #[must_use]
    pub fn to_base32(&self) -> Zeroizing<String> {
        Zeroizing::new(self.secret().to_base32())
    }

    fn secret(&self) -> Secret {
        Secret::from(self.bytes.to_vec())
    }

    fn totp(&self, issuer: Option<String>, account: String) -> Result<Totp, JoseError> {
        Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_digits(DIGITS)
            .with_step_duration(STEP_SECS)
            .with_skew(SKEW_STEPS)
            .with_secret(self.secret())
            .with_issuer(issuer)
            .with_account_name(account)
            .build()
            .map_err(|_| JoseError::Crypto("invalid TOTP parameters"))
    }
}

/// ':' separates issuer and account in the otpauth label, so it is replaced (never rejected).
fn label_part(s: &str) -> String {
    s.trim().replace(':', " ")
}

/// `otpauth://totp/{issuer}:{account}?secret=..&issuer=..` (SHA1, 6 digits, 30 s are the URI
/// defaults and are therefore omitted). Issuer and account are percent-encoded; ':' in either is
/// replaced with a space. Both must be non-empty.
pub fn otpauth_uri(secret: &TotpSecret, issuer: &str, account: &str) -> Result<String, JoseError> {
    let issuer = label_part(issuer);
    let account = label_part(account);
    if issuer.is_empty() {
        return Err(JoseError::Malformed("empty TOTP issuer"));
    }
    if account.is_empty() {
        return Err(JoseError::Malformed("empty TOTP account name"));
    }
    secret
        .totp(Some(issuer), account)?
        .to_url()
        .map_err(|_| JoseError::Malformed("invalid TOTP label"))
}

/// Check a 6-digit `code` at `unix_secs`, allowing ±1 step. Returns the matched time step
/// (`unix_secs / 30` ± 1) or `None` for a wrong, malformed or non-6-digit code.
#[must_use]
pub fn check_code(secret: &TotpSecret, code: &str, unix_secs: u64) -> Option<u64> {
    if code.len() != usize::from(DIGITS) || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    secret
        .totp(None, String::new())
        .ok()?
        .check(code, unix_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B SHA1 seed.
    fn rfc_secret() -> TotpSecret {
        TotpSecret::from_bytes(b"12345678901234567890").unwrap()
    }

    fn code_at(secret: &TotpSecret, t: u64) -> String {
        secret
            .totp(None, String::new())
            .unwrap()
            .generate(t)
            .to_string()
    }

    #[test]
    fn rfc6238_sha1_vector() {
        // RFC 6238 Appendix B: T=59 -> 94287082 (8 digits), i.e. 287082 for 6 digits.
        let s = rfc_secret();
        assert_eq!(code_at(&s, 59), "287082");
        assert_eq!(check_code(&s, "287082", 59), Some(1));
        // T=1111111109 -> 07081804 -> 081804.
        assert_eq!(check_code(&s, "081804", 1_111_111_109), Some(37_037_036));
    }

    #[test]
    fn skew_is_one_step_each_way() {
        let s = TotpSecret::generate();
        let t = 1_800_000_015;
        let step = t / 30;
        let current = code_at(&s, t);
        let previous = code_at(&s, t - 30);
        let next = code_at(&s, t + 30);
        assert_eq!(check_code(&s, &current, t), Some(step));
        assert_eq!(check_code(&s, &previous, t), Some(step - 1));
        assert_eq!(check_code(&s, &next, t), Some(step + 1));
        let too_old = code_at(&s, t - 60);
        let too_new = code_at(&s, t + 60);
        // Guard against an accidental collision with an in-window code.
        if ![&current, &previous, &next].contains(&&too_old) {
            assert_eq!(check_code(&s, &too_old, t), None);
        }
        if ![&current, &previous, &next].contains(&&too_new) {
            assert_eq!(check_code(&s, &too_new, t), None);
        }
    }

    #[test]
    fn wrong_garbage_and_wrong_length_rejected() {
        let s = rfc_secret();
        assert_eq!(check_code(&s, "287083", 59), None);
        for bad in [
            "",
            "28708",
            "2870822",
            "94287082",
            "28708a",
            "+28708",
            " 287082",
            "287 082",
            "２８７０８２",
        ] {
            assert_eq!(check_code(&s, bad, 59), None, "{bad:?}");
        }
        // Another secret does not accept this secret's code.
        assert_eq!(check_code(&TotpSecret::generate(), "287082", 59), None);
    }

    #[test]
    fn generated_secret_shape() {
        let a = TotpSecret::generate();
        let b = TotpSecret::generate();
        assert_eq!(a.as_bytes().len(), 20);
        assert_ne!(a.as_bytes(), b.as_bytes());
        let b32 = a.to_base32();
        assert_eq!(b32.len(), 32);
        assert!(!b32.contains('='));
        assert!(
            b32.bytes()
                .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c))
        );
        assert_eq!(format!("{a:?}"), "TotpSecret(..)");
        assert!(TotpSecret::from_bytes(&[0u8; 15]).is_err());
        assert!(TotpSecret::from_bytes(&[0u8; 65]).is_err());
        assert!(TotpSecret::from_bytes(&[0u8; 16]).is_ok());
    }

    #[test]
    fn otpauth_uri_format() {
        let s = rfc_secret();
        let uri = otpauth_uri(&s, "AnvilID", "alice@example.com").unwrap();
        assert_eq!(
            uri,
            "otpauth://totp/AnvilID:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=AnvilID"
        );
    }

    #[test]
    fn otpauth_colons_replaced_not_rejected() {
        let s = rfc_secret();
        let uri = otpauth_uri(&s, "Acme: Prod", "a:b").unwrap();
        assert!(
            uri.starts_with("otpauth://totp/Acme%20%20Prod:a%20b?"),
            "{uri}"
        );
        assert!(uri.ends_with("&issuer=Acme%20%20Prod"), "{uri}");
        assert!(otpauth_uri(&s, "", "a").is_err());
        assert!(otpauth_uri(&s, "x", " ").is_err());
    }
}
