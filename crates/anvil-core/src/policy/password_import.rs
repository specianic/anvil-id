//! Imported password hashes (ADM-08): the stored legacy-hash encoding, parameter caps and floors.
//! Work in progress (RED commit of plan 07-02).

use std::fmt;

use serde::Serialize;
use uuid::Uuid;

/// Why a hash string or import input was refused. Unit variants only: no error carries input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum HashPolicyError {
    #[error("unknown password hash scheme")]
    UnknownScheme,
    #[error("password hash parameters are below the import floors")]
    WeakParameters,
    #[error("password hash parameters exceed the caps")]
    OverCap,
    #[error("refused password hash variant")]
    RefusedVariant,
    #[error("malformed password hash")]
    Malformed,
}

/// PBKDF2 pseudo-random function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Prf {
    Sha1,
    Sha256,
    Sha512,
}

/// Salted SHA-2 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShaAlg {
    Sha256,
    Sha512,
}

/// Where the salt goes relative to the password bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SaltPosition {
    Prefix,
    Suffix,
}

/// A parsed stored password hash.
#[derive(Clone, PartialEq, Eq)]
pub enum StoredHash<'a> {
    Argon2 {
        phc: &'a str,
        m_kib: u32,
        t: u32,
        p: u32,
    },
    Bcrypt {
        mcf: &'a str,
        cost: u8,
    },
    Scrypt {
        log_n: u8,
        r: u32,
        p: u32,
        salt: Vec<u8>,
        hash: Vec<u8>,
    },
    FirebaseScrypt {
        profile: Uuid,
        salt: Vec<u8>,
        hash: Vec<u8>,
    },
    Pbkdf2 {
        prf: Prf,
        iterations: u32,
        salt: Vec<u8>,
        hash: Vec<u8>,
    },
    Sha2 {
        alg: ShaAlg,
        position: SaltPosition,
        salt: Vec<u8>,
        hash: Vec<u8>,
    },
}

impl fmt::Debug for StoredHash<'_> {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

pub const FIREBASE_PROFILE_PREFIX: &str = "$anvil-firebase-scrypt$";
pub const SCRYPT_MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
pub const ARGON2_MAX_M_KIB: u32 = 262_144;
pub const ARGON2_MAX_T: u32 = 10;
pub const ARGON2_MAX_P: u32 = 8;
pub const PBKDF2_MAX_ITERATIONS: u32 = 5_000_000;
pub const BCRYPT_MAX_COST: u8 = 16;

pub fn parse_stored(_s: &str) -> Result<StoredHash<'_>, HashPolicyError> {
    todo!()
}

pub fn check_stored_caps(_h: &StoredHash<'_>) -> Result<(), HashPolicyError> {
    todo!()
}

pub fn format_stored(_h: &StoredHash<'_>) -> String {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const BCRYPT_TAIL: &str = "CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    const ARGON2I_README: &str =
        "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

    fn argon2(m: u32, t: u32, p: u32) -> String {
        format!("$argon2id$v=19$m={m},t={t},p={p}$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG")
    }

    fn scrypt(log_n: u8, r: u32, p: u32) -> String {
        format_stored(&StoredHash::Scrypt {
            log_n,
            r,
            p,
            salt: vec![7; 16],
            hash: vec![9; 32],
        })
    }

    fn pbkdf2(iterations: u32, hash_len: usize) -> String {
        format_stored(&StoredHash::Pbkdf2 {
            prf: Prf::Sha256,
            iterations,
            salt: vec![7; 16],
            hash: vec![9; hash_len],
        })
    }

    fn caps(s: &str) -> Result<(), HashPolicyError> {
        check_stored_caps(&parse_stored(s).expect("parses"))
    }

    #[test]
    fn parses_argon2_phc() {
        let h = parse_stored(
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
        )
        .unwrap();
        assert!(matches!(
            h,
            StoredHash::Argon2 {
                m_kib: 19456,
                t: 2,
                p: 1,
                ..
            }
        ));
        let h = parse_stored(ARGON2I_README).unwrap();
        assert!(matches!(
            h,
            StoredHash::Argon2 {
                m_kib: 65536,
                t: 2,
                p: 4,
                ..
            }
        ));
        assert_eq!(format_stored(&h), ARGON2I_README);
        assert_eq!(check_stored_caps(&h), Ok(()));
        // v=16 and the version-less legacy form, argon2d.
        assert!(
            parse_stored(
                "$argon2d$v=16$m=4096,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
            )
            .is_ok()
        );
        assert!(
            parse_stored("$argon2i$m=4096,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG")
                .is_ok()
        );
        assert_eq!(
            parse_stored(
                "$argon2id$v=18$m=4096,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
            ),
            Err(HashPolicyError::Malformed)
        );
    }

    #[test]
    fn parses_bcrypt_mcf() {
        for prefix in ["$2a$", "$2b$", "$2y$"] {
            let s = format!("{prefix}05${BCRYPT_TAIL}");
            let h = parse_stored(&s).unwrap();
            assert!(matches!(h, StoredHash::Bcrypt { cost: 5, .. }), "{prefix}");
            assert_eq!(format_stored(&h), s);
        }
    }

    #[test]
    fn caps_refuse_scrypt_over_64_mib() {
        assert_eq!(caps(&scrypt(17, 8, 1)), Err(HashPolicyError::OverCap));
        assert_eq!(caps(&scrypt(16, 8, 2)), Err(HashPolicyError::OverCap));
        // 128 * 2^63 overflows u64: still OverCap, never a wrap-around accept.
        assert_eq!(
            caps(&scrypt(63, u32::MAX, u32::MAX)),
            Err(HashPolicyError::OverCap)
        );
    }

    #[test]
    fn caps_refuse_argon2_memory_over_cap() {
        assert_eq!(
            caps(&argon2(4_194_304, 2, 1)),
            Err(HashPolicyError::OverCap)
        );
        assert_eq!(
            caps(&argon2(ARGON2_MAX_M_KIB + 1, 2, 1)),
            Err(HashPolicyError::OverCap)
        );
    }

    #[test]
    fn caps_refuse_argon2_time_over_cap() {
        assert_eq!(caps(&argon2(19456, 11, 1)), Err(HashPolicyError::OverCap));
    }

    #[test]
    fn caps_refuse_argon2_lanes_over_cap() {
        assert_eq!(caps(&argon2(19456, 2, 9)), Err(HashPolicyError::OverCap));
    }

    #[test]
    fn caps_refuse_pbkdf2_iterations_over_cap() {
        assert_eq!(caps(&pbkdf2(5_000_001, 32)), Err(HashPolicyError::OverCap));
        // A derived key longer than one PRF block multiplies the work: 2 blocks x 2.5M + 1.
        assert_eq!(caps(&pbkdf2(2_500_001, 64)), Err(HashPolicyError::OverCap));
    }

    #[test]
    fn caps_refuse_bcrypt_cost_over_16() {
        assert_eq!(
            caps(&format!("$2b$17${BCRYPT_TAIL}")),
            Err(HashPolicyError::OverCap)
        );
        assert_eq!(
            caps(&format!("$2b$31${BCRYPT_TAIL}")),
            Err(HashPolicyError::OverCap)
        );
    }

    #[test]
    fn caps_accept_boundaries() {
        assert_eq!(caps(&scrypt(16, 8, 1)), Ok(()), "exactly 64 MiB");
        assert_eq!(
            caps(&argon2(ARGON2_MAX_M_KIB, ARGON2_MAX_T, ARGON2_MAX_P)),
            Ok(())
        );
        assert_eq!(caps(&pbkdf2(PBKDF2_MAX_ITERATIONS, 32)), Ok(()));
        assert_eq!(caps(&pbkdf2(PBKDF2_MAX_ITERATIONS / 2, 64)), Ok(()));
        assert_eq!(caps(&format!("$2b$16${BCRYPT_TAIL}")), Ok(()));
    }

    #[test]
    fn parse_refuses_bcrypt_2x() {
        assert_eq!(
            parse_stored(&format!("$2x$10${BCRYPT_TAIL}")),
            Err(HashPolicyError::RefusedVariant)
        );
        assert_eq!(parse_stored("$2x$"), Err(HashPolicyError::RefusedVariant));
    }

    #[test]
    fn parse_unknown_scheme() {
        for s in [
            "$1$saltsalt$hash",
            "$5$rounds=5000$salt$hash",
            "$6$salt$hash",
            "plain",
            "",
            "$anvil-md5$x$y$z",
            "$argon2x$v=19$m=1,t=1,p=1$a$b",
            "$2$05$abc",
            "{SSHA}abcdef",
        ] {
            assert_eq!(
                parse_stored(s),
                Err(HashPolicyError::UnknownScheme),
                "{s:?}"
            );
        }
    }

    #[test]
    fn parse_malformed_never_panics() {
        let good_scrypt = scrypt(14, 8, 1);
        let cases: Vec<String> = vec![
            // truncated fields
            "$anvil-scrypt$".into(),
            "$anvil-scrypt$ln=14,r=8$AAAAAAAAAAA$AAAAAAAAAAA".into(),
            "$anvil-scrypt$ln=14,r=8,p=1$AAAAAAAAAAA".into(),
            "$anvil-pbkdf2$alg=sha256$AAAAAAAAAAA$AAAAAAAAAAA".into(),
            "$anvil-sha2$alg=sha256,pos=prefix$AAAAAAAAAAA".into(),
            "$anvil-firebase-scrypt$profile=not-a-uuid$AAAA$AAAA".into(),
            "$argon2id$v=19$m=19456,t=2$c29tZXNhbHQ$AAAA".into(),
            "$argon2id$v=19$".into(),
            "$2b$1".into(),
            format!("$2b$aa${BCRYPT_TAIL}"),
            format!("$2b$05${}", &BCRYPT_TAIL[1..]),
            format!("$2b$05${}!", &BCRYPT_TAIL[1..]),
            // bad base64: padding, URL alphabet, non-canonical trailing bits
            "$anvil-scrypt$ln=14,r=8,p=1$AAAA==$AAAA".into(),
            "$anvil-scrypt$ln=14,r=8,p=1$AA-_$AAAA".into(),
            "$anvil-scrypt$ln=14,r=8,p=1$AB$AAAA".into(),
            // overlong / non-canonical numbers
            "$anvil-scrypt$ln=256,r=8,p=1$AAAA$AAAA".into(),
            "$anvil-scrypt$ln=14,r=99999999999,p=1$AAAA$AAAA".into(),
            "$anvil-scrypt$ln=014,r=8,p=1$AAAA$AAAA".into(),
            "$anvil-scrypt$ln=+14,r=8,p=1$AAAA$AAAA".into(),
            "$anvil-scrypt$ln=0,r=8,p=1$AAAA$AAAA".into(),
            "$anvil-scrypt$ln=64,r=8,p=1$AAAA$AAAA".into(),
            "$anvil-scrypt$ln=14,r=0,p=1$AAAA$AAAA".into(),
            "$anvil-pbkdf2$alg=sha256,i=0$AAAA$AAAA".into(),
            "$anvil-pbkdf2$alg=md5,i=1000$AAAA$AAAA".into(),
            "$anvil-pbkdf2$i=1000,alg=sha256$AAAA$AAAA".into(),
            "$argon2id$v=19$m=99999999999,t=2,p=1$c29tZXNhbHQ$AAAA".into(),
            "$argon2id$v=19$t=2,m=19456,p=1$c29tZXNhbHQ$AAAA".into(),
            "$argon2id$v=19$m=7,t=2,p=1$c29tZXNhbHQ$AAAA".into(),
            // sha2 digest length must match the algorithm
            "$anvil-sha2$alg=sha256,pos=prefix$AAAAAAAAAAA$AAAA".into(),
            // non-canonical uuid form
            "$anvil-firebase-scrypt$profile=6F9619FF-8B86-D011-B42D-00CF4FC964FF$AAAA$AAAA".into(),
            // trailing segment
            format!("{good_scrypt}$"),
            format!("{good_scrypt}$AAAA"),
            // way too long
            format!("$anvil-scrypt$ln=14,r=8,p=1${}$AAAA", "A".repeat(4000)),
        ];
        for s in &cases {
            assert_eq!(
                parse_stored(s).err(),
                Some(HashPolicyError::Malformed),
                "{s:?}"
            );
        }
        // Every truncation of a valid string: no panic, and anything accepted is canonical.
        for i in 0..good_scrypt.len() {
            let t = &good_scrypt[..i];
            if let Ok(h) = parse_stored(t) {
                assert_eq!(format_stored(&h), t);
            }
        }
    }

    #[test]
    fn policy_error_never_echoes_input() {
        let salt = b"SECRET-SALT-0123".to_vec();
        let hash = b"SECRET-HASH-abcdefghijklmnopqrst".to_vec();
        let salt_b64 = anvil_jose::encoding::b64std(&salt);
        let salt_b64 = salt_b64.trim_end_matches('=');
        let hash_b64 = anvil_jose::encoding::b64std(&hash);
        let hash_b64 = hash_b64.trim_end_matches('=');
        let forbidden = |out: &str| {
            for needle in [
                salt_b64,
                hash_b64,
                "SECRET",
                "c29tZXNhbHQ",
                "RdescudvJCsgt3ub",
                "E5YPO9kmyu",
            ] {
                assert!(!out.contains(needle), "{out:?} leaks {needle:?}");
            }
            assert!(
                !out.contains(&format!("{:?}", salt)),
                "{out:?} leaks salt bytes"
            );
            assert!(
                !out.contains(&format!("{:?}", hash)),
                "{out:?} leaks hash bytes"
            );
        };
        for e in [
            HashPolicyError::UnknownScheme,
            HashPolicyError::WeakParameters,
            HashPolicyError::OverCap,
            HashPolicyError::RefusedVariant,
            HashPolicyError::Malformed,
        ] {
            forbidden(&format!("{e:?}"));
            forbidden(&e.to_string());
            forbidden(&serde_json::to_string(&e).unwrap());
        }
        assert_eq!(
            serde_json::to_string(&HashPolicyError::WeakParameters).unwrap(),
            "\"weak_parameters\""
        );
        assert_eq!(
            serde_json::to_string(&HashPolicyError::OverCap).unwrap(),
            "\"over_cap\""
        );
        let variants = [
            StoredHash::Scrypt {
                log_n: 14,
                r: 8,
                p: 1,
                salt: salt.clone(),
                hash: hash.clone(),
            },
            StoredHash::FirebaseScrypt {
                profile: Uuid::nil(),
                salt: salt.clone(),
                hash: hash.clone(),
            },
            StoredHash::Pbkdf2 {
                prf: Prf::Sha256,
                iterations: 1000,
                salt: salt.clone(),
                hash: hash.clone(),
            },
            StoredHash::Sha2 {
                alg: ShaAlg::Sha256,
                position: SaltPosition::Prefix,
                salt: salt.clone(),
                hash: hash.clone(),
            },
        ];
        for v in &variants {
            let out = format!("{v:?}");
            forbidden(&out);
            assert!(
                out.contains("salt_len: 16") && out.contains("hash_len: 32"),
                "{out}"
            );
        }
        forbidden(&format!("{:?}", parse_stored(ARGON2I_README).unwrap()));
        forbidden(&format!(
            "{:?}",
            parse_stored(&format!("$2b$05${BCRYPT_TAIL}")).unwrap()
        ));
    }

    fn arb_anvil() -> impl Strategy<Value = StoredHash<'static>> {
        let bytes = || proptest::collection::vec(any::<u8>(), 0..80);
        let prf = prop_oneof![Just(Prf::Sha1), Just(Prf::Sha256), Just(Prf::Sha512)];
        let pos = prop_oneof![Just(SaltPosition::Prefix), Just(SaltPosition::Suffix)];
        prop_oneof![
            (1u8..=63, 1u32.., 1u32.., bytes(), bytes()).prop_map(|(log_n, r, p, salt, hash)| {
                StoredHash::Scrypt {
                    log_n,
                    r,
                    p,
                    salt,
                    hash,
                }
            }),
            (any::<u128>(), bytes(), bytes()).prop_map(|(u, salt, hash)| {
                StoredHash::FirebaseScrypt {
                    profile: Uuid::from_u128(u),
                    salt,
                    hash,
                }
            }),
            (prf, 1u32.., bytes(), bytes()).prop_map(|(prf, iterations, salt, hash)| {
                StoredHash::Pbkdf2 {
                    prf,
                    iterations,
                    salt,
                    hash,
                }
            }),
            (
                any::<bool>(),
                pos,
                bytes(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>()
            )
                .prop_map(|(big, position, salt, a, b)| {
                    let (alg, hash) = if big {
                        (ShaAlg::Sha512, [a, b].concat())
                    } else {
                        (ShaAlg::Sha256, a.to_vec())
                    };
                    StoredHash::Sha2 {
                        alg,
                        position,
                        salt,
                        hash,
                    }
                }),
        ]
    }

    proptest! {
        #[test]
        fn anvil_encodings_round_trip(h in arb_anvil()) {
            let s = format_stored(&h);
            let parsed = parse_stored(&s).expect("formatted string parses");
            prop_assert_eq!(&parsed, &h);
            prop_assert_eq!(format_stored(&parsed), s);
        }

        #[test]
        fn parse_is_total(s in "\\PC{0,200}") {
            if let Ok(h) = parse_stored(&s) {
                let _ = check_stored_caps(&h);
                prop_assert_eq!(format_stored(&h), s);
            }
        }

        #[test]
        fn parse_survives_mutations(h in arb_anvil(), at in any::<prop::sample::Index>(), c in any::<char>()) {
            let s = format_stored(&h);
            let mut chars: Vec<char> = s.chars().collect();
            let i = at.index(chars.len());
            chars[i] = c;
            let m: String = chars.into_iter().collect();
            if let Ok(p) = parse_stored(&m) {
                prop_assert_eq!(format_stored(&p), m);
            }
        }
    }
}
