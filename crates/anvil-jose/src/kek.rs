//! Key-encryption key (KEK) envelope for secrets at rest (signing keys, TOTP seeds, ...).
//!
//! Each purpose gets its own AES-256-GCM data key, derived with HKDF-SHA256 (salt `anvilid/v1`,
//! info = purpose). Nonces are random (aws-lc-rs `RandomizedNonceKey`). Sealed format:
//! `nonce (12) || ciphertext || tag (16)`. The caller binds each ciphertext to its row with the AAD
//! (for example `signing_key:{id}`).

use aws_lc_rs::aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use aws_lc_rs::hkdf;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::JoseError;
use crate::encoding::random_bytes;

const KEK_LEN: usize = 32;
const HKDF_SALT: &[u8] = b"anvilid/v1";
const TAG_LEN: usize = 16;

/// A 32-byte key-encryption key. Zeroized on drop; `Debug` never prints the material.
pub struct Kek {
    key: Zeroizing<[u8; KEK_LEN]>,
}

impl std::fmt::Debug for Kek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kek(..)")
    }
}

struct Len32;
impl hkdf::KeyType for Len32 {
    fn len(&self) -> usize {
        KEK_LEN
    }
}

impl Kek {
    /// A fresh random KEK.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            key: Zeroizing::new(random_bytes::<KEK_LEN>()),
        }
    }

    /// From raw bytes. Exactly 32 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self, JoseError> {
        if b.len() != KEK_LEN {
            return Err(JoseError::Crypto("KEK must be exactly 32 bytes"));
        }
        let mut key = Zeroizing::new([0u8; KEK_LEN]);
        key.copy_from_slice(b);
        Ok(Self { key })
    }

    /// From base64 (standard alphabet with padding, or base64url without padding). Surrounding
    /// whitespace is ignored.
    pub fn from_base64(s: &str) -> Result<Self, JoseError> {
        let s = s.trim();
        let bytes = Zeroizing::new(
            STANDARD
                .decode(s)
                .or_else(|_| URL_SAFE_NO_PAD.decode(s))
                .map_err(|_| JoseError::Crypto("KEK is not valid base64"))?,
        );
        Self::from_bytes(&bytes)
    }

    /// Standard base64 (with padding), wrapped so it is not printed by accident.
    #[must_use]
    pub fn to_base64(&self) -> SecretString {
        SecretString::from(STANDARD.encode(self.key.as_ref()))
    }

    fn data_key(&self, purpose: &str) -> Result<RandomizedNonceKey, JoseError> {
        if purpose.is_empty() {
            return Err(JoseError::Crypto("empty KEK purpose"));
        }
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT).extract(self.key.as_ref());
        let info = [purpose.as_bytes()];
        let okm = prk
            .expand(&info, Len32)
            .map_err(|_| JoseError::Crypto("HKDF expand failed"))?;
        let mut dk = Zeroizing::new([0u8; KEK_LEN]);
        okm.fill(dk.as_mut())
            .map_err(|_| JoseError::Crypto("HKDF fill failed"))?;
        RandomizedNonceKey::new(&AES_256_GCM, dk.as_ref())
            .map_err(|_| JoseError::Crypto("AEAD key setup failed"))
    }

    /// Encrypt `plaintext` for `purpose`, bound to `aad`. Returns `nonce || ciphertext || tag`.
    pub fn seal(&self, purpose: &str, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JoseError> {
        let key = self.data_key(purpose)?;
        let mut buf = plaintext.to_vec();
        let nonce = key
            .seal_in_place_append_tag(Aad::from(aad), &mut buf)
            .map_err(|_| JoseError::Crypto("seal failed"))?;
        let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
        out.extend_from_slice(nonce.as_ref());
        out.extend_from_slice(&buf);
        Ok(out)
    }

    /// Decrypt a value produced by [`Kek::seal`] with the same purpose and AAD.
    pub fn open(
        &self,
        purpose: &str,
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, JoseError> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(JoseError::Crypto("sealed value too short"));
        }
        let key = self.data_key(purpose)?;
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        let nonce =
            Nonce::try_assume_unique_for_key(nonce).map_err(|_| JoseError::Crypto("bad nonce"))?;
        let mut buf = Zeroizing::new(ct.to_vec());
        let plain_len = key
            .open_in_place(nonce, Aad::from(aad), buf.as_mut_slice())
            .map_err(|_| JoseError::Crypto("decryption failed"))?
            .len();
        buf.truncate(plain_len);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;

    #[test]
    fn roundtrip() {
        let kek = Kek::generate();
        let sealed = kek
            .seal("signing_key", b"signing_key:1", b"secret")
            .unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + 6 + TAG_LEN);
        let opened = kek.open("signing_key", b"signing_key:1", &sealed).unwrap();
        assert_eq!(opened.as_slice(), b"secret");
        // Random nonces: same input seals differently.
        assert_ne!(
            sealed,
            kek.seal("signing_key", b"signing_key:1", b"secret")
                .unwrap()
        );
    }

    #[test]
    fn wrong_purpose_aad_bits_or_kek_rejected() {
        let kek = Kek::generate();
        let sealed = kek.seal("signing_key", b"row:1", b"secret").unwrap();
        assert!(kek.open("totp_seed", b"row:1", &sealed).is_err());
        assert!(kek.open("signing_key", b"row:2", &sealed).is_err());
        for i in [0, NONCE_LEN, sealed.len() - 1] {
            let mut flipped = sealed.clone();
            flipped[i] ^= 0x01;
            assert!(
                kek.open("signing_key", b"row:1", &flipped).is_err(),
                "bit flip at {i}"
            );
        }
        assert!(
            Kek::generate()
                .open("signing_key", b"row:1", &sealed)
                .is_err()
        );
        assert!(kek.open("signing_key", b"row:1", &sealed[..10]).is_err());
        assert!(kek.seal("", b"row:1", b"x").is_err());
    }

    #[test]
    fn from_bytes_length() {
        assert!(Kek::from_bytes(&[0u8; 31]).is_err());
        assert!(Kek::from_bytes(&[0u8; 33]).is_err());
        assert!(Kek::from_bytes(&[]).is_err());
        assert!(Kek::from_bytes(&[7u8; 32]).is_ok());
    }

    #[test]
    fn base64_roundtrip() {
        let kek = Kek::generate();
        let b64 = kek.to_base64();
        let again = Kek::from_base64(b64.expose_secret()).unwrap();
        let sealed = kek.seal("p", b"", b"x").unwrap();
        assert_eq!(again.open("p", b"", &sealed).unwrap().as_slice(), b"x");
        let url = URL_SAFE_NO_PAD.encode([9u8; 32]);
        assert!(Kek::from_base64(&url).is_ok());
        assert!(Kek::from_base64("not base64!").is_err());
        assert!(Kek::from_base64(&STANDARD.encode([1u8; 16])).is_err());
    }

    #[test]
    fn debug_hides_material() {
        let kek = Kek::from_bytes(&[0xAB; 32]).unwrap();
        let dbg = format!("{kek:?}");
        assert_eq!(dbg, "Kek(..)");
        assert!(!dbg.contains("171") && !dbg.to_lowercase().contains("ab"));
    }
}
