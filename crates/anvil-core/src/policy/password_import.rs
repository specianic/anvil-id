//! Imported password hashes (ADM-08): the one implementation of the stored legacy-hash encoding,
//! the parameter caps and floors, and (below) the conversion of vendor import formats into it.
//!
//! # Stored encoding
//!
//! Imported hashes live in the password credential's existing text column. Argon2 PHC and bcrypt
//! MCF strings are stored as they are; every other scheme is converted **at import time** into one
//! of our own `$anvil-…$` strings, so the login path never parses a vendor format:
//!
//! | Stored form | Meaning |
//! |---|---|
//! | `$argon2id$v=19$m=<kib>,t=<t>,p=<p>$<salt>$<hash>` (also `argon2i`, `argon2d`, `v=16`, no `v`) | Argon2 PHC |
//! | `$2a$`/`$2b$`/`$2y$` + 2-digit cost + `$` + 53 chars (60 chars total) | bcrypt MCF |
//! | `$anvil-scrypt$ln=<log2 N>,r=<r>,p=<p>$<salt>$<hash>` | scrypt |
//! | `$anvil-firebase-scrypt$profile=<uuid>$<salt>$<hash>` | Firebase modified scrypt; the tenant hash profile holds signer key, separator, rounds, mem cost |
//! | `$anvil-pbkdf2$alg=sha1\|sha256\|sha512,i=<iterations>$<salt>$<hash>` | PBKDF2-HMAC |
//! | `$anvil-sha2$alg=sha256\|sha512,pos=prefix\|suffix$<salt>$<hash>` | one SHA-2 pass over `salt‖password` (prefix) or `password‖salt` (suffix) |
//!
//! `<salt>` and `<hash>` in the `$anvil-…$` forms are standard base64 without padding. The
//! `$anvil-…$` grammar is canonical: parameters in the order shown, decimal numbers without sign or
//! leading zeros, lowercase hyphenated UUIDs, canonical base64. So `format_stored(parse_stored(s)) == s`
//! for every accepted `s` (the fuzz target `password_hash_parse` asserts it).
//!
//! # Caps and floors
//!
//! Caps (research Pitfall 1) bound the memory and CPU one verification can cost; they are checked at
//! import (refused with `over_cap`) **and** at verify time through [`check_stored_caps`], which the
//! verifier calls before any work and treats as fail-closed. Floors (research Pitfall 2, decision
//! Q10 defaults) refuse trivially weak data at import with `weak_parameters`, and flag data that is
//! accepted but weak; every legacy hash is rehashed to Argon2id at first login anyway.
//!
//! Nothing in this module (errors, `Debug`, `Display`, serde output) contains hash, salt or password
//! bytes: `Debug` prints lengths only.

use std::fmt;

use anvil_jose::encoding::{b64std, b64std_decode};
use serde::Serialize;
use uuid::Uuid;

/// Why a hash string or import input was refused. Unit variants only, so no error can carry input
/// bytes. The serde form (`unknown_scheme`, `weak_parameters`, ...) is the import report reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum HashPolicyError {
    /// Not a scheme we verify (MD5-crypt, SHA-crypt, plain text, LDAP `{SSHA}`, ...).
    #[error("unknown password hash scheme")]
    UnknownScheme,
    /// Below the import floors (iterations, salt, cost), unsalted, or MD5/SHA-1 digests.
    #[error("password hash parameters are below the import floors")]
    WeakParameters,
    /// Above a memory/CPU cap.
    #[error("password hash parameters exceed the caps")]
    OverCap,
    /// A known but deliberately refused variant (bcrypt `$2x$`).
    #[error("refused password hash variant")]
    RefusedVariant,
    /// Structurally invalid.
    #[error("malformed password hash")]
    Malformed,
}

impl HashPolicyError {
    /// The reason code (same string as the serde form).
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::UnknownScheme => "unknown_scheme",
            Self::WeakParameters => "weak_parameters",
            Self::OverCap => "over_cap",
            Self::RefusedVariant => "refused_variant",
            Self::Malformed => "malformed",
        }
    }
}

/// PBKDF2 pseudo-random function (HMAC with this digest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Prf {
    Sha1,
    Sha256,
    Sha512,
}

impl Prf {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// Output length of one PRF block in bytes.
    #[must_use]
    pub fn block_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// Salted SHA-2 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShaAlg {
    Sha256,
    Sha512,
}

impl ShaAlg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// Digest length in bytes.
    #[must_use]
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// Where the salt goes relative to the password bytes: `prefix` hashes `salt‖password`, `suffix`
/// hashes `password‖salt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SaltPosition {
    Prefix,
    Suffix,
}

impl SaltPosition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prefix => "prefix",
            Self::Suffix => "suffix",
        }
    }
}

/// A parsed stored password hash. Argon2 and bcrypt borrow the full stored string (the adapter
/// verifies it with the argon2/bcrypt crates); the `$anvil-…$` schemes carry decoded bytes.
/// `Debug` prints parameters and lengths, never the bytes or the borrowed string.
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argon2 { m_kib, t, p, .. } => f
                .debug_struct("Argon2")
                .field("m_kib", m_kib)
                .field("t", t)
                .field("p", p)
                .finish_non_exhaustive(),
            Self::Bcrypt { cost, .. } => f
                .debug_struct("Bcrypt")
                .field("cost", cost)
                .finish_non_exhaustive(),
            Self::Scrypt {
                log_n,
                r,
                p,
                salt,
                hash,
            } => f
                .debug_struct("Scrypt")
                .field("log_n", log_n)
                .field("r", r)
                .field("p", p)
                .field("salt_len", &salt.len())
                .field("hash_len", &hash.len())
                .finish(),
            Self::FirebaseScrypt {
                profile,
                salt,
                hash,
            } => f
                .debug_struct("FirebaseScrypt")
                .field("profile", profile)
                .field("salt_len", &salt.len())
                .field("hash_len", &hash.len())
                .finish(),
            Self::Pbkdf2 {
                prf,
                iterations,
                salt,
                hash,
            } => f
                .debug_struct("Pbkdf2")
                .field("prf", prf)
                .field("iterations", iterations)
                .field("salt_len", &salt.len())
                .field("hash_len", &hash.len())
                .finish(),
            Self::Sha2 {
                alg,
                position,
                salt,
                hash,
            } => f
                .debug_struct("Sha2")
                .field("alg", alg)
                .field("position", position)
                .field("salt_len", &salt.len())
                .field("hash_len", &hash.len())
                .finish(),
        }
    }
}

// --- prefixes ------------------------------------------------------------------------------------

const SCRYPT_PREFIX: &str = "$anvil-scrypt$";
/// Prefix of stored Firebase scrypt hashes (the dispatcher routes on it to resolve the hash profile).
pub const FIREBASE_PROFILE_PREFIX: &str = "$anvil-firebase-scrypt$";
const PBKDF2_PREFIX: &str = "$anvil-pbkdf2$";
const SHA2_PREFIX: &str = "$anvil-sha2$";
const ARGON2_PREFIXES: [&str; 3] = ["$argon2id$", "$argon2i$", "$argon2d$"];
const BCRYPT_PREFIXES: [&str; 3] = ["$2a$", "$2b$", "$2y$"];
/// The bugged crypt_blowfish variant (CVE-2011-2483). The `bcrypt` crate accepts it, so it is
/// refused here by prefix.
const BCRYPT_REFUSED_PREFIX: &str = "$2x$";
const BCRYPT_MCF_LEN: usize = 60;

// --- caps (research Pitfall 1) -------------------------------------------------------------------

/// scrypt memory cap: `128 * N * r * p` bytes at most 64 MiB (research Pitfall 1). Computed with
/// checked u64 arithmetic; overflow counts as over the cap. Also applies to Firebase hash profiles
/// (`p = 1`) through [`check_scrypt_params`].
pub const SCRYPT_MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
/// Argon2 memory cap in KiB (256 MiB; research Pitfall 1). Read from stored PHC strings too.
pub const ARGON2_MAX_M_KIB: u32 = 262_144;
/// Argon2 time-cost cap (research Pitfall 1).
pub const ARGON2_MAX_T: u32 = 10;
/// Argon2 lanes cap (research Pitfall 1).
pub const ARGON2_MAX_P: u32 = 8;
/// PBKDF2 work cap (research Pitfall 1): iterations times the number of PRF output blocks the
/// stored hash length needs. For a hash no longer than one PRF block this is the iteration count.
pub const PBKDF2_MAX_ITERATIONS: u32 = 5_000_000;
/// bcrypt cost cap (research Pitfall 1): 2^16 rounds.
pub const BCRYPT_MAX_COST: u8 = 16;
/// Largest accepted salt in bytes (bounds per-verify allocation and HMAC input).
pub const MAX_SALT_BYTES: usize = 256;
/// Largest accepted hash in bytes (a scrypt/PBKDF2 output this long is already unusual).
pub const MAX_HASH_BYTES: usize = 128;
/// Longest accepted stored or vendor hash string (characters of input), checked before any work.
pub const MAX_ENCODED_LEN: usize = 1024;

// --- floors (research Pitfall 2, decision Q10 defaults) --------------------------------------------

/// bcrypt minimum cost (the format minimum; research Pitfall 2). Below: `weak_parameters`.
pub const BCRYPT_MIN_COST: u8 = 4;
/// bcrypt costs below this are accepted but flagged weak (research Pitfall 2).
pub const BCRYPT_WEAK_BELOW_COST: u8 = 10;
/// PBKDF2 minimum iterations (RFC 8018 §4.2 recommendation; research Pitfall 2).
pub const PBKDF2_MIN_ITERATIONS: u32 = 1_000;
/// PBKDF2 iteration counts below this are accepted but flagged weak (research Pitfall 2).
pub const PBKDF2_WEAK_BELOW_ITERATIONS: u32 = 100_000;
/// Minimum salt length for PBKDF2 and salted SHA-2 (research Pitfall 2).
pub const MIN_SALT_BYTES: usize = 8;
/// Minimum stored hash length for scrypt, Firebase scrypt and PBKDF2: a truncated hash lets
/// unrelated passwords match.
pub const MIN_HASH_BYTES: usize = 16;

// --- helpers ---------------------------------------------------------------------------------------

/// Canonical unsigned decimal: digits only, no sign, no leading zero, fits u32.
fn dec_u32(s: &str) -> Result<u32, HashPolicyError> {
    let canonical = !s.is_empty()
        && s.len() <= 10
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'));
    if !canonical {
        return Err(HashPolicyError::Malformed);
    }
    s.parse::<u32>().map_err(|_| HashPolicyError::Malformed)
}

fn dec_u8(s: &str) -> Result<u8, HashPolicyError> {
    u8::try_from(dec_u32(s)?).map_err(|_| HashPolicyError::Malformed)
}

/// Standard base64 without padding, canonical (strict trailing bits). Empty means zero bytes.
fn b64_decode_nopad(s: &str) -> Result<Vec<u8>, HashPolicyError> {
    if s.contains('=') {
        return Err(HashPolicyError::Malformed);
    }
    if s.is_empty() {
        return Ok(Vec::new());
    }
    b64std_decode(s).map_err(|_| HashPolicyError::Malformed)
}

fn b64_encode_nopad(b: &[u8]) -> String {
    let mut s = b64std(b);
    while s.ends_with('=') {
        s.pop();
    }
    s
}

/// Splits `k1=v1,k2=v2,...` with exactly the given keys in order.
fn params<'s, const N: usize>(
    seg: &'s str,
    keys: [&str; N],
) -> Result<[&'s str; N], HashPolicyError> {
    let mut out = [""; N];
    let mut parts = seg.split(',');
    for (slot, key) in out.iter_mut().zip(keys) {
        let part = parts.next().ok_or(HashPolicyError::Malformed)?;
        let (k, v) = part.split_once('=').ok_or(HashPolicyError::Malformed)?;
        if k != key {
            return Err(HashPolicyError::Malformed);
        }
        *slot = v;
    }
    if parts.next().is_some() {
        return Err(HashPolicyError::Malformed);
    }
    Ok(out)
}

/// `<params>$<salt>$<hash>`: exactly three segments, salt and hash decoded.
fn three_segments(rest: &str) -> Result<(&str, Vec<u8>, Vec<u8>), HashPolicyError> {
    let mut it = rest.split('$');
    let (Some(p), Some(salt), Some(hash), None) = (it.next(), it.next(), it.next(), it.next())
    else {
        return Err(HashPolicyError::Malformed);
    };
    Ok((p, b64_decode_nopad(salt)?, b64_decode_nopad(hash)?))
}

fn parse_prf(s: &str) -> Result<Prf, HashPolicyError> {
    match s {
        "sha1" => Ok(Prf::Sha1),
        "sha256" => Ok(Prf::Sha256),
        "sha512" => Ok(Prf::Sha512),
        _ => Err(HashPolicyError::Malformed),
    }
}

/// `128 * 2^log_n * r * p`, `None` on overflow or a shift past 63.
fn scrypt_memory_bytes(log_n: u8, r: u32, p: u32) -> Option<u64> {
    let n = 1u64.checked_shl(u32::from(log_n)).filter(|_| log_n < 64)?;
    128u64
        .checked_mul(n)?
        .checked_mul(u64::from(r))?
        .checked_mul(u64::from(p))
}

/// scrypt parameter validity and the memory cap. Used for stored `$anvil-scrypt$` hashes and for
/// Firebase hash profiles (`log_n = mem_cost`, `r = rounds`, `p = 1`).
pub fn check_scrypt_params(log_n: u8, r: u32, p: u32) -> Result<(), HashPolicyError> {
    if log_n == 0 || log_n > 63 || r == 0 || p == 0 {
        return Err(HashPolicyError::Malformed);
    }
    match scrypt_memory_bytes(log_n, r, p) {
        Some(bytes) if bytes <= SCRYPT_MAX_MEMORY_BYTES => Ok(()),
        _ => Err(HashPolicyError::OverCap),
    }
}

// --- parse / format --------------------------------------------------------------------------------

/// Parses a stored hash string (login path). Recognises only the forms in the module docs, never
/// vendor import formats. Total: returns an error for any other input, never panics. Structural
/// only: callers check [`check_stored_caps`] before verifying.
pub fn parse_stored(s: &str) -> Result<StoredHash<'_>, HashPolicyError> {
    if let Some(rest) = s.strip_prefix(SCRYPT_PREFIX) {
        limit(s)?;
        let (p, salt, hash) = three_segments(rest)?;
        let [ln, r, pp] = params(p, ["ln", "r", "p"])?;
        let (log_n, r, p) = (dec_u8(ln)?, dec_u32(r)?, dec_u32(pp)?);
        if log_n == 0 || log_n > 63 || r == 0 || p == 0 {
            return Err(HashPolicyError::Malformed);
        }
        return Ok(StoredHash::Scrypt {
            log_n,
            r,
            p,
            salt,
            hash,
        });
    }
    if let Some(rest) = s.strip_prefix(FIREBASE_PROFILE_PREFIX) {
        limit(s)?;
        let (p, salt, hash) = three_segments(rest)?;
        let [profile] = params(p, ["profile"])?;
        let uuid = Uuid::try_parse(profile).map_err(|_| HashPolicyError::Malformed)?;
        if uuid.hyphenated().to_string() != profile {
            return Err(HashPolicyError::Malformed);
        }
        return Ok(StoredHash::FirebaseScrypt {
            profile: uuid,
            salt,
            hash,
        });
    }
    if let Some(rest) = s.strip_prefix(PBKDF2_PREFIX) {
        limit(s)?;
        let (p, salt, hash) = three_segments(rest)?;
        let [alg, i] = params(p, ["alg", "i"])?;
        let prf = parse_prf(alg)?;
        let iterations = dec_u32(i)?;
        if iterations == 0 {
            return Err(HashPolicyError::Malformed);
        }
        return Ok(StoredHash::Pbkdf2 {
            prf,
            iterations,
            salt,
            hash,
        });
    }
    if let Some(rest) = s.strip_prefix(SHA2_PREFIX) {
        limit(s)?;
        let (p, salt, hash) = three_segments(rest)?;
        let [alg, pos] = params(p, ["alg", "pos"])?;
        let alg = match alg {
            "sha256" => ShaAlg::Sha256,
            "sha512" => ShaAlg::Sha512,
            _ => return Err(HashPolicyError::Malformed),
        };
        let position = match pos {
            "prefix" => SaltPosition::Prefix,
            "suffix" => SaltPosition::Suffix,
            _ => return Err(HashPolicyError::Malformed),
        };
        if hash.len() != alg.digest_len() {
            return Err(HashPolicyError::Malformed);
        }
        return Ok(StoredHash::Sha2 {
            alg,
            position,
            salt,
            hash,
        });
    }
    if let Some(prefix) = ARGON2_PREFIXES.iter().find(|p| s.starts_with(**p)) {
        limit(s)?;
        return parse_argon2(s, &s[prefix.len()..]);
    }
    if s.starts_with(BCRYPT_REFUSED_PREFIX) {
        return Err(HashPolicyError::RefusedVariant);
    }
    if BCRYPT_PREFIXES.iter().any(|p| s.starts_with(p)) {
        return parse_bcrypt(s);
    }
    Err(HashPolicyError::UnknownScheme)
}

fn limit(s: &str) -> Result<(), HashPolicyError> {
    if s.len() > MAX_ENCODED_LEN {
        Err(HashPolicyError::Malformed)
    } else {
        Ok(())
    }
}

/// Reads only what the caps need (m, t, p) and checks the PHC structure; the argon2 crate verifies.
fn parse_argon2<'a>(phc: &'a str, rest: &str) -> Result<StoredHash<'a>, HashPolicyError> {
    let segs: Vec<&str> = rest.split('$').collect();
    let (params_seg, salt, hash) = match segs.as_slice() {
        [v, p, salt, hash] => {
            if *v != "v=19" && *v != "v=16" {
                return Err(HashPolicyError::Malformed);
            }
            (*p, *salt, *hash)
        }
        [p, salt, hash] => (*p, *salt, *hash),
        _ => return Err(HashPolicyError::Malformed),
    };
    let [m, t, p] = params(params_seg, ["m", "t", "p"])?;
    let (m_kib, t, p) = (dec_u32(m)?, dec_u32(t)?, dec_u32(p)?);
    // RFC 9106 §3.1: p >= 1, t >= 1, m >= 8p; salt at least 8 bytes, tag at least 4 bytes.
    if t == 0 || p == 0 || u64::from(m_kib) < 8 * u64::from(p) {
        return Err(HashPolicyError::Malformed);
    }
    if b64_decode_nopad(salt)?.len() < 8 || b64_decode_nopad(hash)?.len() < 4 {
        return Err(HashPolicyError::Malformed);
    }
    Ok(StoredHash::Argon2 { phc, m_kib, t, p })
}

fn parse_bcrypt(mcf: &str) -> Result<StoredHash<'_>, HashPolicyError> {
    let b = mcf.as_bytes();
    if b.len() != BCRYPT_MCF_LEN || b[6] != b'$' {
        return Err(HashPolicyError::Malformed);
    }
    let cost = std::str::from_utf8(&b[4..6])
        .ok()
        .filter(|c| c.bytes().all(|x| x.is_ascii_digit()))
        .and_then(|c| c.parse::<u8>().ok())
        .ok_or(HashPolicyError::Malformed)?;
    // bcrypt's own base64 alphabet: `./A-Za-z0-9`.
    if !b[7..]
        .iter()
        .all(|x| x.is_ascii_alphanumeric() || *x == b'.' || *x == b'/')
    {
        return Err(HashPolicyError::Malformed);
    }
    Ok(StoredHash::Bcrypt { mcf, cost })
}

/// Formats a stored hash. Argon2 and bcrypt return the borrowed input string unchanged.
#[must_use]
pub fn format_stored(h: &StoredHash<'_>) -> String {
    match h {
        StoredHash::Argon2 { phc, .. } => (*phc).to_string(),
        StoredHash::Bcrypt { mcf, .. } => (*mcf).to_string(),
        StoredHash::Scrypt {
            log_n,
            r,
            p,
            salt,
            hash,
        } => format!(
            "{SCRYPT_PREFIX}ln={log_n},r={r},p={p}${}${}",
            b64_encode_nopad(salt),
            b64_encode_nopad(hash)
        ),
        StoredHash::FirebaseScrypt {
            profile,
            salt,
            hash,
        } => format!(
            "{FIREBASE_PROFILE_PREFIX}profile={}${}${}",
            profile.hyphenated(),
            b64_encode_nopad(salt),
            b64_encode_nopad(hash)
        ),
        StoredHash::Pbkdf2 {
            prf,
            iterations,
            salt,
            hash,
        } => format!(
            "{PBKDF2_PREFIX}alg={},i={iterations}${}${}",
            prf.as_str(),
            b64_encode_nopad(salt),
            b64_encode_nopad(hash)
        ),
        StoredHash::Sha2 {
            alg,
            position,
            salt,
            hash,
        } => format!(
            "{SHA2_PREFIX}alg={},pos={}${}${}",
            alg.as_str(),
            position.as_str(),
            b64_encode_nopad(salt),
            b64_encode_nopad(hash)
        ),
    }
}

// --- caps / floors -----------------------------------------------------------------------------------

fn lengths_within_caps(salt: &[u8], hash: &[u8]) -> Result<(), HashPolicyError> {
    if salt.len() > MAX_SALT_BYTES || hash.len() > MAX_HASH_BYTES {
        Err(HashPolicyError::OverCap)
    } else {
        Ok(())
    }
}

/// The caps (research Pitfall 1). Called at import and by the verifier before any work; an error
/// at verify time means "do not verify" (fail closed).
pub fn check_stored_caps(h: &StoredHash<'_>) -> Result<(), HashPolicyError> {
    match h {
        StoredHash::Argon2 { m_kib, t, p, .. } => {
            if *m_kib > ARGON2_MAX_M_KIB || *t > ARGON2_MAX_T || *p > ARGON2_MAX_P {
                return Err(HashPolicyError::OverCap);
            }
            Ok(())
        }
        StoredHash::Bcrypt { cost, .. } => {
            if *cost > BCRYPT_MAX_COST {
                return Err(HashPolicyError::OverCap);
            }
            Ok(())
        }
        StoredHash::Scrypt {
            log_n,
            r,
            p,
            salt,
            hash,
        } => {
            check_scrypt_params(*log_n, *r, *p)?;
            lengths_within_caps(salt, hash)
        }
        StoredHash::FirebaseScrypt { salt, hash, .. } => lengths_within_caps(salt, hash),
        StoredHash::Pbkdf2 {
            prf,
            iterations,
            salt,
            hash,
        } => {
            lengths_within_caps(salt, hash)?;
            let blocks = hash.len().div_ceil(prf.block_len()).max(1) as u64;
            if u64::from(*iterations) * blocks > u64::from(PBKDF2_MAX_ITERATIONS) {
                return Err(HashPolicyError::OverCap);
            }
            Ok(())
        }
        StoredHash::Sha2 { salt, hash, .. } => lengths_within_caps(salt, hash),
    }
}

/// The import floors (research Pitfall 2, decision Q10). `Ok(weak)` accepts the hash and says
/// whether it is flagged weak; `Err(WeakParameters)` refuses it. Argon2, scrypt and Firebase scrypt
/// are never flagged weak; salted SHA-2 always is.
pub fn check_import_floors(h: &StoredHash<'_>) -> Result<bool, HashPolicyError> {
    let weak = Err(HashPolicyError::WeakParameters);
    match h {
        StoredHash::Argon2 { .. } => Ok(false),
        StoredHash::Bcrypt { cost, .. } => {
            if *cost < BCRYPT_MIN_COST {
                return weak;
            }
            Ok(*cost < BCRYPT_WEAK_BELOW_COST)
        }
        StoredHash::Scrypt { salt, hash, .. } | StoredHash::FirebaseScrypt { salt, hash, .. } => {
            if salt.is_empty() || hash.len() < MIN_HASH_BYTES {
                return weak;
            }
            Ok(false)
        }
        StoredHash::Pbkdf2 {
            iterations,
            salt,
            hash,
            ..
        } => {
            if *iterations < PBKDF2_MIN_ITERATIONS
                || salt.len() < MIN_SALT_BYTES
                || hash.len() < MIN_HASH_BYTES
            {
                return weak;
            }
            Ok(*iterations < PBKDF2_WEAK_BELOW_ITERATIONS)
        }
        StoredHash::Sha2 { salt, .. } => {
            if salt.len() < MIN_SALT_BYTES {
                return weak;
            }
            Ok(true)
        }
    }
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
