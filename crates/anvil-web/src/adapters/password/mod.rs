//! Password verification for every stored scheme (ADM-08): [`PasswordDispatcher`], the one
//! production [`PasswordHasher`], plus one legacy verifier module per imported scheme.
//!
//! ## The dispatcher
//!
//! [`PasswordDispatcher`] wraps the bounded [`Argon2Pool`] and, for each `verify`:
//! 1. `None` (unknown user) and stored values that are not a recognised scheme (unknown or garbled)
//!    take the Argon2 dummy-hash path and return `valid = false`, so an unknown email and a known
//!    account with an unparseable hash look the same.
//! 2. Parses the stored string with `policy::password_import::parse_stored` and applies
//!    `check_stored_caps` BEFORE any hashing (Argon2 parameters included). Over-cap hashes and
//!    refused variants (bcrypt `$2x$`) fail closed: `valid = false`, one warn log with the scheme and
//!    reason code, and no hashing at all (nothing is allocated for the hostile parameters).
//!    Firebase scrypt also needs the hash profile material from core; without it, or with profile
//!    parameters over the scrypt cap, it fails closed the same way.
//! 3. Routes to the Argon2 path or to a legacy verifier. Every verification, whatever the scheme,
//!    runs inside the pool's one semaphore + `spawn_blocking` (`Overloaded` when the queue is full).
//! 4. A legacy match always returns `needs_rehash = true` (core then stores an Argon2id hash);
//!    Argon2 keeps its parameter-based `needs_rehash`.
//!
//! A profile passed for a non-Firebase hash is ignored (core resolves profiles only for
//! `$anvil-firebase-scrypt$` strings). Known accounts may differ in timing by scheme (research
//! Pitfall 5, accepted: the account exists either way); unknown accounts always use the dummy.
//!
//! ## Legacy verifiers
//!
//! One pure, synchronous function per legacy scheme. They take primitive arguments (the dispatcher
//! parses the stored `$anvil-…$` / MCF string and receives the hash profile from core) and answer
//! "does this password match": `Ok(true)` / `Ok(false)`, or an error when the parameters cannot be
//! evaluated at all.
//!
//! - Every derived-versus-expected comparison is constant time (`subtle::ConstantTimeEq`, or the
//!   `bcrypt` crate's own `subtle` compare). Unequal lengths compare as "not equal".
//! - These functions do NOT apply the import caps and floors. The single implementation of those is
//!   `anvil_core::policy::password_import`; the dispatcher applies it before calling in here and runs
//!   the call inside the bounded hashing pool.
//! - Nothing here logs, formats or returns the password, the salt or the hash. [`LegacyVerifyError`]
//!   carries a reason code only.
//!
//! Crypto backends (ARCHITECTURE.md §2): PBKDF2, SHA-2 and the AES-256-CTR step of Firebase scrypt
//! run on aws-lc-rs. scrypt and bcrypt are the only RustCrypto primitives, a scoped
//! verification-only exception (deny.toml wrappers for `salsa20` and `blowfish`).

pub mod bcrypt;
pub mod firebase;
pub mod pbkdf2;
pub mod scrypt;
pub mod sha2;

use anvil_core::error::CoreError;
use anvil_core::model::HashProfileMaterial;
use anvil_core::policy::password_import::{
    self as policy, HashPolicyError, StoredHash, check_scrypt_params, check_stored_caps,
    parse_stored,
};
use anvil_core::ports::{PasswordCheck, PasswordHasher};
use zeroize::Zeroizing;

use crate::adapters::argon2::Argon2Pool;

const INVALID: PasswordCheck = PasswordCheck {
    valid: false,
    needs_rehash: false,
};

/// The production [`PasswordHasher`]: Argon2id for new hashes, scheme dispatch for verification
/// (module docs). `Debug` prints the pool size only.
pub struct PasswordDispatcher {
    argon2: Argon2Pool,
}

impl std::fmt::Debug for PasswordDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordDispatcher")
            .field("permits", &self.argon2.permits())
            .finish()
    }
}

impl PasswordDispatcher {
    /// Wraps `argon2`; its permits bound every verification of every scheme.
    pub fn new(argon2: Argon2Pool) -> Self {
        Self { argon2 }
    }

    /// Verifications computed so far (Argon2, dummy and legacy), see [`Argon2Pool::verifications`].
    pub fn verifications(&self) -> u64 {
        self.argon2.verifications()
    }
}

/// A legacy verification with owned inputs, so it can move onto the blocking pool. Deliberately no
/// `Debug`: it holds hash, salt and profile bytes.
enum LegacyJob {
    Bcrypt {
        mcf: String,
    },
    Scrypt {
        log_n: u8,
        r: u32,
        p: u32,
        salt: Vec<u8>,
        hash: Vec<u8>,
    },
    Firebase {
        salt: Vec<u8>,
        hash: Vec<u8>,
        salt_separator: Vec<u8>,
        signer_key: Zeroizing<Vec<u8>>,
        rounds: u32,
        mem_cost: u8,
    },
    Pbkdf2 {
        prf: pbkdf2::Prf,
        iterations: u32,
        salt: Vec<u8>,
        hash: Vec<u8>,
    },
    Sha2 {
        alg: sha2::Digest,
        position: sha2::SaltPosition,
        salt: Vec<u8>,
        hash: Vec<u8>,
    },
}

impl LegacyJob {
    fn scheme(&self) -> &'static str {
        match self {
            Self::Bcrypt { .. } => "bcrypt",
            Self::Scrypt { .. } => "scrypt",
            Self::Firebase { .. } => "firebase_scrypt",
            Self::Pbkdf2 { .. } => "pbkdf2",
            Self::Sha2 { .. } => "salted_sha2",
        }
    }

    fn run(&self, password: &[u8]) -> Result<bool, LegacyVerifyError> {
        match self {
            Self::Bcrypt { mcf } => bcrypt::verify(password, mcf),
            Self::Scrypt {
                log_n,
                r,
                p,
                salt,
                hash,
            } => scrypt::verify(password, salt, *log_n, *r, *p, hash),
            Self::Firebase {
                salt,
                hash,
                salt_separator,
                signer_key,
                rounds,
                mem_cost,
            } => firebase::verify(
                password,
                salt,
                salt_separator,
                signer_key,
                *rounds,
                *mem_cost,
                hash,
            ),
            Self::Pbkdf2 {
                prf,
                iterations,
                salt,
                hash,
            } => pbkdf2::verify(*prf, *iterations, password, salt, hash),
            Self::Sha2 {
                alg,
                position,
                salt,
                hash,
            } => sha2::verify(*alg, *position, password, salt, hash),
        }
    }
}

fn stored_scheme(h: &StoredHash<'_>) -> &'static str {
    match h {
        StoredHash::Argon2 { .. } => "argon2",
        StoredHash::Bcrypt { .. } => "bcrypt",
        StoredHash::Scrypt { .. } => "scrypt",
        StoredHash::FirebaseScrypt { .. } => "firebase_scrypt",
        StoredHash::Pbkdf2 { .. } => "pbkdf2",
        StoredHash::Sha2 { .. } => "salted_sha2",
    }
}

/// Fail closed without hashing: one warn log with the scheme and a reason code, never input bytes.
fn refuse(scheme: &'static str, reason: &'static str) -> PasswordCheck {
    tracing::warn!(
        scheme,
        reason,
        "stored password hash refused; verification failed closed"
    );
    INVALID
}

#[async_trait::async_trait]
impl PasswordHasher for PasswordDispatcher {
    async fn hash(&self, password: &str) -> Result<String, CoreError> {
        self.argon2.hash(password).await
    }

    async fn verify(
        &self,
        stored: Option<&str>,
        password: &str,
        profile: Option<&HashProfileMaterial>,
    ) -> Result<PasswordCheck, CoreError> {
        let Some(stored) = stored else {
            return self.argon2.verify_dummy(password).await;
        };
        let parsed = match parse_stored(stored) {
            Ok(h) => h,
            Err(HashPolicyError::RefusedVariant) => {
                return Ok(refuse("bcrypt", HashPolicyError::RefusedVariant.reason()));
            }
            Err(e) => {
                tracing::error!(
                    reason = e.reason(),
                    "stored password hash not recognised; dummy verification"
                );
                return self.argon2.verify_dummy(password).await;
            }
        };
        if let Err(e) = check_stored_caps(&parsed) {
            return Ok(refuse(stored_scheme(&parsed), e.reason()));
        }
        let job = match parsed {
            StoredHash::Argon2 { phc, .. } => {
                return self.argon2.verify_argon2(phc, password).await;
            }
            StoredHash::Bcrypt { mcf, .. } => LegacyJob::Bcrypt {
                mcf: mcf.to_owned(),
            },
            StoredHash::Scrypt {
                log_n,
                r,
                p,
                salt,
                hash,
            } => LegacyJob::Scrypt {
                log_n,
                r,
                p,
                salt,
                hash,
            },
            StoredHash::FirebaseScrypt { salt, hash, .. } => {
                let Some(material) = profile else {
                    return Ok(refuse("firebase_scrypt", "missing_profile"));
                };
                if let Err(e) = check_scrypt_params(material.mem_cost, material.rounds, 1) {
                    return Ok(refuse("firebase_scrypt", e.reason()));
                }
                LegacyJob::Firebase {
                    salt,
                    hash,
                    salt_separator: material.salt_separator.clone(),
                    signer_key: Zeroizing::new(material.signer_key().to_vec()),
                    rounds: material.rounds,
                    mem_cost: material.mem_cost,
                }
            }
            StoredHash::Pbkdf2 {
                prf,
                iterations,
                salt,
                hash,
            } => LegacyJob::Pbkdf2 {
                prf: match prf {
                    policy::Prf::Sha1 => pbkdf2::Prf::Sha1,
                    policy::Prf::Sha256 => pbkdf2::Prf::Sha256,
                    policy::Prf::Sha512 => pbkdf2::Prf::Sha512,
                },
                iterations,
                salt,
                hash,
            },
            StoredHash::Sha2 {
                alg,
                position,
                salt,
                hash,
            } => LegacyJob::Sha2 {
                alg: match alg {
                    policy::ShaAlg::Sha256 => sha2::Digest::Sha256,
                    policy::ShaAlg::Sha512 => sha2::Digest::Sha512,
                },
                position: match position {
                    policy::SaltPosition::Prefix => sha2::SaltPosition::Prefix,
                    policy::SaltPosition::Suffix => sha2::SaltPosition::Suffix,
                },
                salt,
                hash,
            },
        };
        let scheme = job.scheme();
        let password = Zeroizing::new(password.as_bytes().to_vec());
        match self
            .argon2
            .run_verification(move || job.run(&password))
            .await?
        {
            Ok(valid) => Ok(PasswordCheck {
                valid,
                needs_rehash: valid,
            }),
            Err(e) => {
                tracing::warn!(
                    scheme,
                    reason = %e,
                    "stored password hash could not be evaluated"
                );
                Ok(INVALID)
            }
        }
    }
}

/// Why a legacy hash could not be evaluated. Reason codes only, never input material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LegacyVerifyError {
    /// A cost/size parameter is outside what the algorithm can evaluate (e.g. scrypt `r = 0`).
    #[error("invalid_parameters")]
    InvalidParameters,
    /// The stored hash string is not well formed for its scheme.
    #[error("malformed_hash")]
    Malformed,
    /// A known but deliberately refused variant (bcrypt `$2x$`).
    #[error("refused_variant")]
    RefusedVariant,
}

/// Upper bound on the length of a stored derived key the KDF verifiers accept. Real schemes store
/// 16..=64 bytes; anything longer is not a password hash and would only make the KDF do more work.
pub(crate) const MAX_DERIVED_LEN: usize = 1024;

/// Constant-time equality; unequal lengths are "not equal" (the length is not secret).
pub(crate) fn ct_eq(derived: &[u8], expected: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    derived.ct_eq(expected).into()
}

#[cfg(test)]
pub(crate) mod test_util {
    /// Decodes a lowercase/uppercase hex string (test vectors only).
    pub(crate) fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    /// Returns a copy with the last byte flipped.
    pub(crate) fn flip_last(v: &[u8]) -> Vec<u8> {
        let mut out = v.to_vec();
        if let Some(b) = out.last_mut() {
            *b ^= 0x01;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::LegacyVerifyError;

    #[test]
    fn legacy_verify_error_debug_has_no_input() {
        let cases = [
            (
                LegacyVerifyError::InvalidParameters,
                "InvalidParameters",
                "invalid_parameters",
            ),
            (LegacyVerifyError::Malformed, "Malformed", "malformed_hash"),
            (
                LegacyVerifyError::RefusedVariant,
                "RefusedVariant",
                "refused_variant",
            ),
        ];
        for (err, debug, display) in cases {
            assert_eq!(format!("{err:?}"), debug);
            assert_eq!(err.to_string(), display);
        }
    }

    #[test]
    fn ct_eq_folds_length_into_the_result() {
        assert!(super::ct_eq(b"abc", b"abc"));
        assert!(!super::ct_eq(b"abc", b"abd"));
        assert!(!super::ct_eq(b"abc", b"ab"));
        assert!(!super::ct_eq(b"", b"a"));
    }
}

#[cfg(test)]
mod dispatcher_tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ::argon2::Params;
    use anvil_core::error::CoreError;
    use anvil_core::model::HashProfileMaterial;
    use anvil_core::policy::password_import::{
        Prf, SaltPosition, ShaAlg, StoredHash, format_stored,
    };
    use anvil_core::ports::{PasswordCheck, PasswordHasher as _};
    use anvil_jose::encoding::b64std_decode;

    use super::PasswordDispatcher;
    use super::test_util::hex;
    use crate::adapters::argon2::Argon2Pool;

    fn low() -> Params {
        Params::new(256, 1, 1, None).expect("params")
    }

    fn dispatcher(permits: usize) -> PasswordDispatcher {
        PasswordDispatcher::new(Argon2Pool::new(low(), permits).expect("pool"))
    }

    fn d(s: &str) -> Vec<u8> {
        b64std_decode(s).expect("vector base64")
    }

    const VALID_LEGACY: PasswordCheck = PasswordCheck {
        valid: true,
        needs_rehash: true,
    };
    const INVALID: PasswordCheck = PasswordCheck {
        valid: false,
        needs_rehash: false,
    };

    // Source: Openwall crypt_blowfish 1.3 wrapper.c ("U*U", cost 05).
    const BCRYPT_OPENWALL: &str = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    // Source: P-H-C/phc-winner-argon2 README example: "password", salt "somesalt", t=2, m=65536, p=4.
    const ARGON2I_README: &str =
        "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
    // Source: firebase/scrypt README and tests/01-known-value.sh (published demo hash profile).
    const FB_SIGNER_KEY: &str =
        "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
    const FB_SEPARATOR: &str = "Bw==";
    const FB_SALT: &str = "42xEC+ixf3L2lw==";
    const FB_HUNTER2: &str =
        "70k8Vg5B3/OrvJOiqusnasv0dLcBHoDAqJrJr7TRLBfMw4MitWx51YXJYFdGiyMbMeKtWtLf5HiBDcN0SUOm4A==";

    fn firebase_material(mem_cost: u8) -> HashProfileMaterial {
        HashProfileMaterial {
            salt_separator: d(FB_SEPARATOR),
            signer_key: secrecy::SecretBox::from(d(FB_SIGNER_KEY).into_boxed_slice()),
            rounds: 8,
            mem_cost,
        }
    }

    fn firebase_stored() -> String {
        format_stored(&StoredHash::FirebaseScrypt {
            profile: uuid::Uuid::from_u128(0x0709),
            salt: d(FB_SALT),
            hash: d(FB_HUNTER2),
        })
    }

    // Source: RFC 7914 §12, P = "password", S = "NaCl", N = 1024, r = 8, p = 16, dkLen = 64.
    fn scrypt_stored() -> String {
        format_stored(&StoredHash::Scrypt {
            log_n: 10,
            r: 8,
            p: 16,
            salt: b"NaCl".to_vec(),
            hash: hex(
                "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162\
                 2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
            ),
        })
    }

    // Source: RFC 6070 §2, PBKDF2-HMAC-SHA1, P = "password", S = "salt", c = 4096, dkLen = 20.
    fn pbkdf2_stored() -> String {
        format_stored(&StoredHash::Pbkdf2 {
            prf: Prf::Sha1,
            iterations: 4096,
            salt: b"salt".to_vec(),
            hash: hex("4b007901b765489abead49d926f721d065a429c1"),
        })
    }

    // Source: FIPS 180-4 SHA-256("abc"); suffix position = H(password || salt), "ab" || "c".
    fn sha256_suffix_stored() -> String {
        format_stored(&StoredHash::Sha2 {
            alg: ShaAlg::Sha256,
            position: SaltPosition::Suffix,
            salt: b"c".to_vec(),
            hash: hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        })
    }

    async fn check(
        d: &PasswordDispatcher,
        stored: &str,
        password: &str,
        profile: Option<&HashProfileMaterial>,
    ) -> PasswordCheck {
        d.verify(Some(stored), password, profile)
            .await
            .expect("verify")
    }

    #[tokio::test]
    async fn dispatcher_verifies_bcrypt_openwall_vector() {
        let d = dispatcher(2);
        assert_eq!(check(&d, BCRYPT_OPENWALL, "U*U", None).await, VALID_LEGACY);
        assert_eq!(check(&d, BCRYPT_OPENWALL, "U*V", None).await, INVALID);
    }

    #[tokio::test]
    async fn dispatcher_verifies_scrypt_rfc7914_vector() {
        let d = dispatcher(2);
        let stored = scrypt_stored();
        assert_eq!(check(&d, &stored, "password", None).await, VALID_LEGACY);
        assert_eq!(check(&d, &stored, "passwore", None).await, INVALID);
    }

    #[tokio::test]
    async fn dispatcher_verifies_firebase_vector_with_profile() {
        let d = dispatcher(2);
        let stored = firebase_stored();
        let material = firebase_material(14);
        assert_eq!(
            check(&d, &stored, "hunter2", Some(&material)).await,
            VALID_LEGACY
        );
        assert_eq!(
            check(&d, &stored, "hunter3", Some(&material)).await,
            INVALID
        );
    }

    #[tokio::test]
    async fn dispatcher_verifies_pbkdf2_sha1_4096_vector() {
        let d = dispatcher(2);
        let stored = pbkdf2_stored();
        assert_eq!(check(&d, &stored, "password", None).await, VALID_LEGACY);
        assert_eq!(check(&d, &stored, "passwore", None).await, INVALID);
    }

    #[tokio::test]
    async fn dispatcher_verifies_sha256_suffix_vector() {
        let d = dispatcher(2);
        let stored = sha256_suffix_stored();
        assert_eq!(check(&d, &stored, "ab", None).await, VALID_LEGACY);
        assert_eq!(check(&d, &stored, "abc", None).await, INVALID);
    }

    #[tokio::test]
    async fn dispatcher_argon2_fresh_hash_keeps_todays_behaviour() {
        let d = dispatcher(2);
        let phc = d.hash("correct horse").await.expect("hash");
        assert!(phc.starts_with("$argon2id$v=19$m=256,t=1,p=1$"), "{phc}");
        let ok = check(&d, &phc, "correct horse", None).await;
        assert!(ok.valid && !ok.needs_rehash, "current params: no rehash");
        assert_eq!(check(&d, &phc, "wrong", None).await, INVALID);
        // Hashed with other (still capped) parameters: valid, rehash requested.
        let old_pool =
            Argon2Pool::new(Params::new(128, 1, 1, None).expect("params"), 1).expect("pool");
        let other = old_pool.hash("pw").await.expect("hash");
        assert_eq!(
            check(&d, &other, "pw", None).await,
            PasswordCheck {
                valid: true,
                needs_rehash: true
            }
        );
    }

    #[tokio::test]
    async fn dispatcher_verifies_phc_readme_argon2i_vector() {
        let d = dispatcher(1);
        assert_eq!(
            check(&d, ARGON2I_README, "password", None).await,
            PasswordCheck {
                valid: true,
                needs_rehash: true
            },
            "argon2i is not the current variant, so a match asks for a rehash"
        );
    }

    #[tokio::test]
    async fn dispatcher_legacy_match_requests_rehash() {
        let d = dispatcher(2);
        let material = firebase_material(14);
        let cases: [(String, &str, Option<&HashProfileMaterial>); 5] = [
            (BCRYPT_OPENWALL.to_owned(), "U*U", None),
            (scrypt_stored(), "password", None),
            (firebase_stored(), "hunter2", Some(&material)),
            (pbkdf2_stored(), "password", None),
            (sha256_suffix_stored(), "ab", None),
        ];
        for (stored, password, profile) in cases {
            let ok = check(&d, &stored, password, profile).await;
            assert!(ok.valid && ok.needs_rehash, "{stored}");
            let bad = check(&d, &stored, "definitely wrong", profile).await;
            assert!(
                !bad.valid && !bad.needs_rehash,
                "no rehash on a mismatch: {stored}"
            );
        }
    }

    /// Over-cap: no hashing at all (the counter does not move, not even for the dummy) and the call
    /// returns long before any hashing at these parameters could finish.
    async fn assert_fails_closed_without_hashing(
        d: &PasswordDispatcher,
        stored: &str,
        profile: Option<&HashProfileMaterial>,
    ) {
        let before = d.verifications();
        let t = Instant::now();
        assert_eq!(
            check(d, stored, "password", profile).await,
            INVALID,
            "{stored}"
        );
        assert!(t.elapsed() < Duration::from_millis(200), "{stored}");
        assert_eq!(d.verifications(), before, "no hashing ran: {stored}");
    }

    #[tokio::test]
    async fn dispatcher_argon2_over_cap_fails_closed_without_hashing() {
        let d = dispatcher(1);
        for stored in [
            // m = 4 GiB
            "$argon2id$v=19$m=4194304,t=1,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            // t over the cap
            "$argon2id$v=19$m=256,t=11,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            // p over the cap
            "$argon2i$v=19$m=256,t=1,p=9$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
        ] {
            assert_fails_closed_without_hashing(&d, stored, None).await;
        }
    }

    #[tokio::test]
    async fn dispatcher_scrypt_over_cap_fails_closed_without_hashing() {
        let d = dispatcher(1);
        // 128 * 2^20 * 8 = 1 GiB, and an r*p product the crate would refuse anyway.
        for (log_n, r, p) in [(20u8, 8u32, 1u32), (14, 8, 64), (10, 1 << 20, 1 << 12)] {
            let stored = format_stored(&StoredHash::Scrypt {
                log_n,
                r,
                p,
                salt: vec![7; 16],
                hash: vec![9; 32],
            });
            assert_fails_closed_without_hashing(&d, &stored, None).await;
        }
    }

    #[tokio::test]
    async fn dispatcher_pbkdf2_over_cap_fails_closed() {
        let d = dispatcher(1);
        for (prf, iterations, len) in [
            (Prf::Sha256, 5_000_001u32, 32usize),
            (Prf::Sha1, u32::MAX, 20),
            // Within the iteration cap, but 4 output blocks multiply the work past it.
            (Prf::Sha256, 2_000_000, 128),
        ] {
            let stored = format_stored(&StoredHash::Pbkdf2 {
                prf,
                iterations,
                salt: vec![7; 16],
                hash: vec![9; len],
            });
            assert_fails_closed_without_hashing(&d, &stored, None).await;
        }
    }

    #[tokio::test]
    async fn dispatcher_bcrypt_over_cap_fails_closed() {
        let d = dispatcher(1);
        let stored = "$2b$17$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
        assert_fails_closed_without_hashing(&d, stored, None).await;
    }

    #[tokio::test]
    async fn dispatcher_refuses_bcrypt_2x() {
        let d = dispatcher(1);
        // The bcrypt crate itself accepts $2x$ and would answer true for "U*U".
        let stored = "$2x$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
        let before = d.verifications();
        assert_eq!(check(&d, stored, "U*U", None).await, INVALID);
        assert_eq!(d.verifications(), before, "refused before any hashing");
    }

    #[tokio::test]
    async fn dispatcher_unknown_scheme_takes_dummy_path() {
        let d = dispatcher(1);
        for stored in [
            "$6$rounds=5000$saltsalt$KJdVjcSO4tSqyfw9IQqU1n5GdYq0Y0bT/2pRbwQ1Tg9",
            "garbage",
            "",
            // Garbled Argon2 and $anvil-… strings are "not recognised" too.
            "$argon2id$v=19$m=x,t=1,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub",
            "$anvil-pbkdf2$alg=md5,i=1000$c2FsdHNhbHQ$AAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let before = d.verifications();
            assert_eq!(
                check(&d, stored, "password", None).await,
                INVALID,
                "{stored}"
            );
            assert_eq!(
                d.verifications(),
                before + 1,
                "the dummy verification ran: {stored:?}"
            );
        }
        // An unknown user takes exactly the same path.
        let before = d.verifications();
        assert_eq!(
            d.verify(None, "password", None).await.expect("verify"),
            INVALID
        );
        assert_eq!(d.verifications(), before + 1);
    }

    #[tokio::test]
    async fn dispatcher_firebase_without_profile_fails_closed() {
        let d = dispatcher(1);
        // Even the right password: without the profile material nothing is computed.
        assert_fails_closed_without_hashing(&d, &firebase_stored(), None).await;
        let before = d.verifications();
        assert_eq!(
            check(&d, &firebase_stored(), "hunter2", None).await,
            INVALID
        );
        assert_eq!(d.verifications(), before);
    }

    #[tokio::test]
    async fn dispatcher_firebase_profile_over_cap_fails_closed() {
        let d = dispatcher(1);
        // mem_cost 20, rounds 8: 128 * 2^20 * 8 = 1 GiB.
        let material = firebase_material(20);
        assert_fails_closed_without_hashing(&d, &firebase_stored(), Some(&material)).await;
    }

    #[tokio::test]
    async fn dispatcher_ignores_profile_for_non_firebase_hashes() {
        let d = dispatcher(1);
        let material = firebase_material(14);
        assert_eq!(
            check(&d, BCRYPT_OPENWALL, "U*U", Some(&material)).await,
            VALID_LEGACY
        );
        let phc = d.hash("pw").await.expect("hash");
        assert!(check(&d, &phc, "pw", Some(&material)).await.valid);
    }

    /// Holds the single permit with a blocking closure until the returned sender is used.
    async fn hold_permit(
        d: &Arc<PasswordDispatcher>,
    ) -> (
        std::sync::mpsc::Sender<()>,
        tokio::task::JoinHandle<Result<(), CoreError>>,
    ) {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let holder = tokio::spawn({
            let d = Arc::clone(d);
            async move {
                d.argon2
                    .run_bounded(move || {
                        let _ = rx.recv();
                    })
                    .await
            }
        });
        wait_until_busy(d).await;
        (tx, holder)
    }

    async fn wait_until_busy(d: &PasswordDispatcher) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while d.argon2.available_permits() != 0 {
            assert!(Instant::now() < deadline, "the permit was never taken");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    fn dispatcher_with_timeout(permits: usize, timeout: Duration) -> PasswordDispatcher {
        PasswordDispatcher::new(
            Argon2Pool::with_acquire_timeout(low(), permits, timeout).expect("pool"),
        )
    }

    #[tokio::test]
    async fn dispatcher_overloaded_when_queue_full() {
        let d = Arc::new(dispatcher_with_timeout(1, Duration::from_millis(50)));
        let phc = d.hash("pw").await.expect("hash");
        let (release, holder) = hold_permit(&d).await;
        let before = d.verifications();
        for stored in [
            Some(phc.as_str()),
            Some(BCRYPT_OPENWALL),
            Some(&sha256_suffix_stored()),
            Some("garbage"),
            None,
        ] {
            let err = d.verify(stored, "pw", None).await.expect_err("saturated");
            assert!(matches!(err, CoreError::Overloaded), "{stored:?}: {err:?}");
        }
        assert!(matches!(
            d.hash("pw").await.expect_err("saturated"),
            CoreError::Overloaded
        ));
        assert_eq!(d.verifications(), before, "nothing ran without a permit");
        release.send(()).expect("release");
        holder.await.expect("join").expect("holder");
        assert!(check(&d, &phc, "pw", None).await.valid);
        assert_eq!(check(&d, BCRYPT_OPENWALL, "U*U", None).await, VALID_LEGACY);
    }

    #[tokio::test]
    async fn dispatcher_serialises_legacy_and_argon2_on_one_permit() {
        let d = Arc::new(dispatcher_with_timeout(1, Duration::from_millis(100)));
        let phc = d.hash("pw").await.expect("hash");

        // A slow legacy verification (PBKDF2, 3,000,000 iterations, under the cap) holds the one
        // permit: an Argon2 verification cannot start and sheds load.
        let slow_pbkdf2 = format_stored(&StoredHash::Pbkdf2 {
            prf: Prf::Sha1,
            iterations: 3_000_000,
            salt: vec![7; 16],
            hash: vec![9; 20],
        });
        let legacy = tokio::spawn({
            let d = Arc::clone(&d);
            async move { d.verify(Some(&slow_pbkdf2), "pw", None).await }
        });
        wait_until_busy(&d).await;
        let err = d.verify(Some(&phc), "pw", None).await.expect_err("busy");
        assert!(matches!(err, CoreError::Overloaded), "{err:?}");
        assert_eq!(legacy.await.expect("join").expect("legacy"), INVALID);

        // And the other way round: a slow Argon2 verification (the 64 MiB README vector) holds
        // the permit, so a legacy verification sheds load.
        let argon = tokio::spawn({
            let d = Arc::clone(&d);
            async move { d.verify(Some(ARGON2I_README), "password", None).await }
        });
        wait_until_busy(&d).await;
        let err = d
            .verify(Some(&sha256_suffix_stored()), "ab", None)
            .await
            .expect_err("busy");
        assert!(matches!(err, CoreError::Overloaded), "{err:?}");
        assert!(argon.await.expect("join").expect("argon2").valid);

        // Once free, both run normally.
        assert!(check(&d, &phc, "pw", None).await.valid);
        assert_eq!(
            check(&d, &sha256_suffix_stored(), "ab", None).await,
            VALID_LEGACY
        );
    }

    #[tokio::test]
    async fn dispatcher_debug_redacts() {
        let d = dispatcher(2);
        assert_eq!(format!("{d:?}"), "PasswordDispatcher { permits: 2 }");
    }
}
