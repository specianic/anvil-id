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

// --- import conversion ---------------------------------------------------------------------------

/// A raw byte field of an import input: `{"hex": "…"}` (either case) or `{"base64": "…"}`
/// (standard alphabet, padded or unpadded). `Debug` prints the encoding and length only.
#[derive(Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ByteField {
    Hex(String),
    Base64(String),
}

impl ByteField {
    fn decode(&self) -> Result<Vec<u8>, HashPolicyError> {
        match self {
            Self::Hex(s) => {
                limit(s)?;
                if s.len() % 2 != 0 {
                    return Err(HashPolicyError::Malformed);
                }
                s.as_bytes()
                    .chunks(2)
                    .map(|pair| match (hex_val(pair[0]), hex_val(pair[1])) {
                        (Some(hi), Some(lo)) => Ok(hi << 4 | lo),
                        _ => Err(HashPolicyError::Malformed),
                    })
                    .collect()
            }
            Self::Base64(s) => {
                limit(s)?;
                if s.is_empty() {
                    return Ok(Vec::new());
                }
                b64std_decode(s).map_err(|_| HashPolicyError::Malformed)
            }
        }
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Debug for ByteField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hex(s) => write!(f, "hex({} chars)", s.len()),
            Self::Base64(s) => write!(f, "base64({} chars)", s.len()),
        }
    }
}

/// Digest named by a `salted_sha2` import. MD5 and SHA-1 parse so they can be refused with
/// `weak_parameters` rather than a generic error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SaltedDigest {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

/// The import schemes, as accepted in the `scheme` field of [`ImportPassword`].
pub const IMPORT_SCHEMES: [&str; 8] = [
    "bcrypt",
    "argon2",
    "scrypt",
    "firebase_scrypt",
    "pbkdf2",
    "django_pbkdf2",
    "passlib_pbkdf2",
    "salted_sha2",
];

/// The `password` object of an import record, tagged by `scheme`. Unknown fields are rejected.
/// See the accepted shapes in the module docs below. `Debug` prints the scheme and field lengths
/// only.
///
/// # Accepted input shapes
///
/// Byte fields (`salt`, `hash` where shown as *bytes*) are `{"hex": "…"}` or `{"base64": "…"}`.
///
/// | `scheme` | Fields | Stored as |
/// |---|---|---|
/// | `bcrypt` | `hash`: MCF string `$2a$`/`$2b$`/`$2y$` | as is; cost 4..=16, weak below 10; `$2x$` refused (`refused_variant`) |
/// | `argon2` | `hash`: PHC string (argon2i/d/id, `v=16`/`v=19`) | as is after the m/t/p caps |
/// | `scrypt` | `salt` *bytes*, `hash` *bytes*, `log_n` (log2 N, 1..=63), `r`, `p` | `$anvil-scrypt$` |
/// | `firebase_scrypt` | `salt` *bytes* (the user's salt), `hash` *bytes* (`passwordHash`), `profile` (UUID of the tenant hash profile holding signer key, salt separator, rounds, mem cost) | `$anvil-firebase-scrypt$` |
/// | `pbkdf2` | `prf` (`sha1`/`sha256`/`sha512`), `iterations`, `salt` *bytes*, `hash` *bytes* | `$anvil-pbkdf2$` |
/// | `django_pbkdf2` | `hash`: `pbkdf2_sha256$<iterations>$<salt>$<base64 hash>` (or `pbkdf2_sha1`); the salt string's UTF-8 bytes are the salt | `$anvil-pbkdf2$` |
/// | `passlib_pbkdf2` | `hash`: `$pbkdf2-sha256$<iterations>$<ab64 salt>$<ab64 hash>` (also `$pbkdf2$` = SHA-1, `$pbkdf2-sha512$`); ab64 is base64 with `.` for `+`, no padding | `$anvil-pbkdf2$` |
/// | `salted_sha2` | `alg` (`sha256`/`sha512`; `md5`/`sha1` refused), `position` (`prefix` = `H(salt‖password)`, `suffix` = `H(password‖salt)`), `salt` *bytes* (required, at least 8 bytes), `hash` *bytes* (digest length) | `$anvil-sha2$`, always weak |
///
/// Refusals: an unknown `scheme` (including `md5`, `sha1`, `sha256` as a scheme) is `unknown_scheme`
/// through [`parse_import_value`]; unsalted digests and MD5/SHA-1 salted digests are
/// `weak_parameters`; unknown Django/passlib algorithm identifiers are `unknown_scheme`.
#[derive(Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(tag = "scheme", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportPassword {
    Bcrypt {
        hash: String,
    },
    Argon2 {
        hash: String,
    },
    Scrypt {
        salt: ByteField,
        hash: ByteField,
        log_n: u8,
        r: u32,
        p: u32,
    },
    FirebaseScrypt {
        salt: ByteField,
        hash: ByteField,
        profile: Uuid,
    },
    Pbkdf2 {
        prf: Prf,
        iterations: u32,
        salt: ByteField,
        hash: ByteField,
    },
    DjangoPbkdf2 {
        hash: String,
    },
    PasslibPbkdf2 {
        hash: String,
    },
    SaltedSha2 {
        alg: SaltedDigest,
        position: SaltPosition,
        #[serde(default)]
        salt: Option<ByteField>,
        hash: ByteField,
    },
}

impl ImportPassword {
    /// The `scheme` tag.
    #[must_use]
    pub fn scheme(&self) -> &'static str {
        match self {
            Self::Bcrypt { .. } => "bcrypt",
            Self::Argon2 { .. } => "argon2",
            Self::Scrypt { .. } => "scrypt",
            Self::FirebaseScrypt { .. } => "firebase_scrypt",
            Self::Pbkdf2 { .. } => "pbkdf2",
            Self::DjangoPbkdf2 { .. } => "django_pbkdf2",
            Self::PasslibPbkdf2 { .. } => "passlib_pbkdf2",
            Self::SaltedSha2 { .. } => "salted_sha2",
        }
    }
}

impl fmt::Debug for ImportPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("ImportPassword");
        d.field("scheme", &self.scheme());
        match self {
            Self::Bcrypt { hash }
            | Self::Argon2 { hash }
            | Self::DjangoPbkdf2 { hash }
            | Self::PasslibPbkdf2 { hash } => {
                d.field("hash_len", &hash.len());
            }
            Self::Scrypt { salt, hash, .. }
            | Self::FirebaseScrypt { salt, hash, .. }
            | Self::Pbkdf2 { salt, hash, .. } => {
                d.field("salt", salt).field("hash", hash);
            }
            Self::SaltedSha2 { salt, hash, .. } => {
                d.field("salt", salt).field("hash", hash);
            }
        }
        d.finish_non_exhaustive()
    }
}

/// Parses the `password` object of an import record, mapping an unknown `scheme` to
/// `unknown_scheme` and any other shape error (missing or unknown fields, wrong types) to
/// `malformed`. The serde error itself is dropped: it can quote input.
pub fn parse_import_value(v: serde_json::Value) -> Result<ImportPassword, HashPolicyError> {
    todo!()
}

/// The result of converting an import input: the stored string and whether the floors flag it
/// weak. `Debug` redacts the stored string.
#[derive(Clone, PartialEq, Eq)]
pub struct Converted {
    pub stored: String,
    pub weak: bool,
}

impl fmt::Debug for Converted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Converted")
            .field("stored_len", &self.stored.len())
            .field("weak", &self.weak)
            .finish()
    }
}

/// Converts an import input into the stored encoding, enforcing the caps (`over_cap`) and the
/// floors (`weak_parameters`). The one conversion path for the admin API and the CLI.
pub fn convert_import(input: &ImportPassword) -> Result<Converted, HashPolicyError> {
    todo!()
}

/// A `bcrypt`/`argon2` input that is not that scheme at all is malformed input, not an unknown
/// scheme of ours.
fn declared(r: Result<StoredHash<'_>, HashPolicyError>) -> Result<StoredHash<'_>, HashPolicyError> {
    r.map_err(|e| match e {
        HashPolicyError::UnknownScheme => HashPolicyError::Malformed,
        other => other,
    })
}

fn finish(h: &StoredHash<'_>) -> Result<Converted, HashPolicyError> {
    check_stored_caps(h)?;
    let weak = check_import_floors(h)?;
    Ok(Converted {
        stored: format_stored(h),
        weak,
    })
}

fn pbkdf2(
    prf: Prf,
    iterations: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
) -> Result<Converted, HashPolicyError> {
    if iterations == 0 || hash.is_empty() {
        return Err(HashPolicyError::Malformed);
    }
    finish(&StoredHash::Pbkdf2 {
        prf,
        iterations,
        salt,
        hash,
    })
}

/// Django `pbkdf2_sha256$<iterations>$<salt>$<base64 hash>`.
fn convert_django(s: &str) -> Result<Converted, HashPolicyError> {
    limit(s)?;
    let mut it = s.split('$');
    let (Some(alg), Some(i), Some(salt), Some(hash), None) =
        (it.next(), it.next(), it.next(), it.next(), it.next())
    else {
        // Django's other hashers (`md5$salt$hash`, `unsalted_sha1$$hash`, ...) mostly have
        // fewer segments; refuse them by name where possible.
        return match s.split_once('$') {
            Some((alg, _)) if !alg.starts_with("pbkdf2_") => Err(HashPolicyError::UnknownScheme),
            _ => Err(HashPolicyError::Malformed),
        };
    };
    let prf = match alg {
        "pbkdf2_sha256" => Prf::Sha256,
        "pbkdf2_sha1" => Prf::Sha1,
        _ => return Err(HashPolicyError::UnknownScheme),
    };
    let iterations = dec_u32(i)?;
    let hash = if hash.is_empty() {
        Vec::new()
    } else {
        b64std_decode(hash).map_err(|_| HashPolicyError::Malformed)?
    };
    pbkdf2(prf, iterations, salt.as_bytes().to_vec(), hash)
}

/// passlib `$pbkdf2-sha256$<iterations>$<ab64 salt>$<ab64 hash>`.
fn convert_passlib(s: &str) -> Result<Converted, HashPolicyError> {
    limit(s)?;
    let mut it = s.split('$');
    let (Some(""), Some(ident), Some(i), Some(salt), Some(hash), None) = (
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
    ) else {
        return Err(HashPolicyError::Malformed);
    };
    let prf = match ident {
        "pbkdf2" => Prf::Sha1,
        "pbkdf2-sha256" => Prf::Sha256,
        "pbkdf2-sha512" => Prf::Sha512,
        _ => return Err(HashPolicyError::UnknownScheme),
    };
    let iterations = dec_u32(i)?;
    pbkdf2(prf, iterations, ab64_decode(salt)?, ab64_decode(hash)?)
}

/// passlib "adapted base64": the standard alphabet with `.` instead of `+`, no padding.
fn ab64_decode(s: &str) -> Result<Vec<u8>, HashPolicyError> {
    if s.contains('+') {
        return Err(HashPolicyError::Malformed);
    }
    b64_decode_nopad(&s.replace('.', "+"))
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

    // --- import conversion ---------------------------------------------------------------------

    fn import(v: serde_json::Value) -> Result<Converted, HashPolicyError> {
        convert_import(&parse_import_value(v)?)
    }

    fn ok(v: serde_json::Value) -> Converted {
        import(v).expect("converts")
    }

    const FIREBASE_SALT: &str = "42xEC+ixf3L2lw==";
    const FIREBASE_HASH: &str =
        "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";
    const RFC7914_HASH: &str = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640";

    #[test]
    fn import_bcrypt_and_argon2_as_is() {
        let s = format!("$2a$05${BCRYPT_TAIL}");
        let c = ok(serde_json::json!({"scheme": "bcrypt", "hash": s}));
        assert_eq!(
            c,
            Converted {
                stored: s,
                weak: true
            },
            "cost 5 is below 10"
        );
        let s = format!("$2b$10${BCRYPT_TAIL}");
        assert!(!ok(serde_json::json!({"scheme": "bcrypt", "hash": s})).weak);
        assert_eq!(
            import(
                serde_json::json!({"scheme": "bcrypt", "hash": format!("$2b$03${BCRYPT_TAIL}")})
            ),
            Err(HashPolicyError::WeakParameters)
        );
        assert_eq!(
            import(
                serde_json::json!({"scheme": "bcrypt", "hash": format!("$2x$10${BCRYPT_TAIL}")})
            ),
            Err(HashPolicyError::RefusedVariant)
        );
        let c = ok(serde_json::json!({"scheme": "argon2", "hash": ARGON2I_README}));
        assert_eq!(
            c,
            Converted {
                stored: ARGON2I_README.into(),
                weak: false
            }
        );
    }

    #[test]
    fn import_cannot_smuggle_another_scheme() {
        let anvil = scrypt(14, 8, 1);
        for (scheme, hash) in [
            ("bcrypt", anvil.clone()),
            ("argon2", anvil),
            ("bcrypt", ARGON2I_README.to_string()),
            ("argon2", format!("$2b$10${BCRYPT_TAIL}")),
            ("bcrypt", "$1$saltsalt$hash".to_string()),
        ] {
            assert_eq!(
                import(serde_json::json!({"scheme": scheme, "hash": hash})),
                Err(HashPolicyError::Malformed),
                "{scheme} {hash}"
            );
        }
    }

    #[test]
    fn import_scrypt_rfc7914_vector() {
        let c = ok(serde_json::json!({
            "scheme": "scrypt", "salt": {"base64": "TmFDbA=="}, "hash": {"hex": RFC7914_HASH},
            "log_n": 10, "r": 8, "p": 16
        }));
        assert_eq!(
            c.stored,
            "$anvil-scrypt$ln=10,r=8,p=16$TmFDbA$/bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWIurzDZLiKjiG/xCSedmDDaxyevuUqD7m2DYMvfoswGQA"
        );
        assert!(!c.weak);
        // Uppercase hex is the same bytes.
        let upper = ok(serde_json::json!({
            "scheme": "scrypt", "salt": {"hex": "4e61436c"}, "hash": {"hex": RFC7914_HASH.to_uppercase()},
            "log_n": 10, "r": 8, "p": 16
        }));
        assert_eq!(upper, c);
    }

    #[test]
    fn import_firebase_scrypt_vector() {
        let c = ok(serde_json::json!({
            "scheme": "firebase_scrypt", "salt": {"base64": FIREBASE_SALT}, "hash": {"base64": FIREBASE_HASH},
            "profile": "0b9a6b7e-1c2d-4e3f-8a9b-0c1d2e3f4a5b"
        }));
        assert_eq!(
            c.stored,
            "$anvil-firebase-scrypt$profile=0b9a6b7e-1c2d-4e3f-8a9b-0c1d2e3f4a5b$42xEC+ixf3L2lw$lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ"
        );
        assert!(!c.weak);
        assert!(c.stored.starts_with(FIREBASE_PROFILE_PREFIX));
    }

    #[test]
    fn import_pbkdf2_generic_django_and_passlib() {
        // PBKDF2-HMAC-SHA256("password", 0x10..0x1f, 29000), computed with Python hashlib.
        let expected = "$anvil-pbkdf2$alg=sha256,i=29000$EBESExQVFhcYGRobHB0eHw$lK/NCVPwPoiutAFj+DgqoDnIMTMGIqcHDo8y1yR2iSY";
        let generic = ok(serde_json::json!({
            "scheme": "pbkdf2", "prf": "sha256", "iterations": 29000,
            "salt": {"base64": "EBESExQVFhcYGRobHB0eHw"},
            "hash": {"base64": "lK/NCVPwPoiutAFj+DgqoDnIMTMGIqcHDo8y1yR2iSY="}
        }));
        assert_eq!(
            generic,
            Converted {
                stored: expected.into(),
                weak: true
            }
        );
        let passlib = ok(serde_json::json!({
            "scheme": "passlib_pbkdf2",
            "hash": "$pbkdf2-sha256$29000$EBESExQVFhcYGRobHB0eHw$lK/NCVPwPoiutAFj.DgqoDnIMTMGIqcHDo8y1yR2iSY"
        }));
        assert_eq!(
            passlib, generic,
            "adapted base64 converts to the same stored string"
        );
        // Django: PBKDF2-HMAC-SHA256("password", b"seasalt2026abcdefghij", 600000).
        let django = ok(serde_json::json!({
            "scheme": "django_pbkdf2",
            "hash": "pbkdf2_sha256$600000$seasalt2026abcdefghij$vzhv8lHKtIQgPgn8kaqzhwkhLxdlkVYL69D6MdJ5Hz4="
        }));
        assert_eq!(
            django,
            Converted {
                stored: "$anvil-pbkdf2$alg=sha256,i=600000$c2Vhc2FsdDIwMjZhYmNkZWZnaGlq$vzhv8lHKtIQgPgn8kaqzhwkhLxdlkVYL69D6MdJ5Hz4".into(),
                weak: false
            }
        );
        // Unknown identifiers.
        assert_eq!(
            import(
                serde_json::json!({"scheme": "passlib_pbkdf2", "hash": "$pbkdf2-md5$1000$EBESExQVFhcYGRobHB0eHw$AAAA"})
            ),
            Err(HashPolicyError::UnknownScheme)
        );
        assert_eq!(
            import(
                serde_json::json!({"scheme": "django_pbkdf2", "hash": "argon2$argon2id$v=19$m=1,t=1,p=1$a$b"})
            ),
            Err(HashPolicyError::UnknownScheme)
        );
        // passlib's alphabet has no '+'.
        assert_eq!(
            import(
                serde_json::json!({"scheme": "passlib_pbkdf2", "hash": "$pbkdf2-sha256$29000$EBESExQVFhcYGRobHB0eHw$lK/NCVPwPoiutAFj+DgqoDnIMTMGIqcHDo8y1yR2iSY"})
            ),
            Err(HashPolicyError::Malformed)
        );
    }

    #[test]
    fn import_salted_sha2_is_always_weak() {
        // SHA-256(salt || "password"), computed with Python hashlib.
        let c = ok(serde_json::json!({
            "scheme": "salted_sha2", "alg": "sha256", "position": "prefix",
            "salt": {"hex": "00112233445566778899aabbccddeeff"},
            "hash": {"hex": "9db024047938d4cad75a5684778b36d7f38b7f792ad69fd1a8aebe48bdc011eb"}
        }));
        assert_eq!(
            c,
            Converted {
                stored: "$anvil-sha2$alg=sha256,pos=prefix$ABEiM0RVZneImaq7zN3u/w$nbAkBHk41MrXWlaEd4s21/OLf3kq1p/RqK6+SL3AEes".into(),
                weak: true
            }
        );
        // Digest length must match the algorithm.
        assert_eq!(
            import(serde_json::json!({
                "scheme": "salted_sha2", "alg": "sha512", "position": "suffix",
                "salt": {"hex": "00112233445566778899aabbccddeeff"},
                "hash": {"hex": "9db024047938d4cad75a5684778b36d7f38b7f792ad69fd1a8aebe48bdc011eb"}
            })),
            Err(HashPolicyError::Malformed)
        );
    }

    fn pbkdf2_input(iterations: u32, salt_len: usize) -> serde_json::Value {
        serde_json::json!({
            "scheme": "pbkdf2", "prf": "sha256", "iterations": iterations,
            "salt": {"hex": "ab".repeat(salt_len)}, "hash": {"hex": "cd".repeat(32)}
        })
    }

    fn sha2_input(alg: &str, salt: Option<&str>) -> serde_json::Value {
        let mut v = serde_json::json!({
            "scheme": "salted_sha2", "alg": alg, "position": "suffix",
            "hash": {"hex": "cd".repeat(32)}
        });
        if let Some(s) = salt {
            v["salt"] = serde_json::json!({"hex": s});
        }
        v
    }

    #[test]
    fn import_refuses_pbkdf2_below_1000_iterations() {
        assert_eq!(
            import(pbkdf2_input(999, 16)),
            Err(HashPolicyError::WeakParameters)
        );
        assert_eq!(import(pbkdf2_input(1000, 16)).map(|c| c.weak), Ok(true));
        assert_eq!(import(pbkdf2_input(99_999, 16)).map(|c| c.weak), Ok(true));
        assert_eq!(import(pbkdf2_input(100_000, 16)).map(|c| c.weak), Ok(false));
        // RFC 6070 vector: 4-byte salt "salt" is below the salt floor.
        assert_eq!(
            import(serde_json::json!({
                "scheme": "pbkdf2", "prf": "sha1", "iterations": 4096, "salt": {"hex": "73616c74"},
                "hash": {"hex": "4b007901b765489abead49d926f721d065a429c1"}
            })),
            Err(HashPolicyError::WeakParameters)
        );
    }

    #[test]
    fn import_refuses_short_salt() {
        assert_eq!(
            import(pbkdf2_input(600_000, 7)),
            Err(HashPolicyError::WeakParameters)
        );
        assert!(import(pbkdf2_input(600_000, 8)).is_ok());
        let seven = "ab".repeat(7);
        let eight = "ab".repeat(8);
        assert_eq!(
            import(sha2_input("sha256", Some(&seven))),
            Err(HashPolicyError::WeakParameters)
        );
        assert!(import(sha2_input("sha256", Some(&eight))).is_ok());
        assert_eq!(
            import(serde_json::json!({
                "scheme": "django_pbkdf2", "hash": "pbkdf2_sha256$600000$1234567$vzhv8lHKtIQgPgn8kaqzhwkhLxdlkVYL69D6MdJ5Hz4="
            })),
            Err(HashPolicyError::WeakParameters)
        );
    }

    #[test]
    fn import_refuses_unsalted_sha256() {
        assert_eq!(
            import(sha2_input("sha256", None)),
            Err(HashPolicyError::WeakParameters)
        );
        assert_eq!(
            import(sha2_input("sha256", Some(""))),
            Err(HashPolicyError::WeakParameters)
        );
        assert_eq!(
            import(serde_json::json!({"scheme": "sha256", "hash": {"hex": "cd".repeat(32)}})),
            Err(HashPolicyError::UnknownScheme)
        );
    }

    /// MD5: refused as `unknown_scheme` when named as a scheme (no `md5` import scheme exists, and
    /// Django's `md5$…` hasher is not PBKDF2), and as `weak_parameters` when named as the digest of
    /// a salted import.
    #[test]
    fn import_refuses_md5() {
        assert_eq!(
            import(
                serde_json::json!({"scheme": "md5", "hash": "5f4dcc3b5aa765d61d8327deb882cf99"})
            ),
            Err(HashPolicyError::UnknownScheme)
        );
        let salt = "ab".repeat(16);
        assert_eq!(
            import(sha2_input("md5", Some(&salt))),
            Err(HashPolicyError::WeakParameters)
        );
        assert_eq!(
            import(
                serde_json::json!({"scheme": "django_pbkdf2", "hash": "md5$seasalt$5f4dcc3b5aa765d61d8327deb882cf99"})
            ),
            Err(HashPolicyError::UnknownScheme)
        );
    }

    /// Plain SHA-1: same rule as MD5.
    #[test]
    fn import_refuses_plain_sha1() {
        assert_eq!(
            import(
                serde_json::json!({"scheme": "sha1", "hash": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"})
            ),
            Err(HashPolicyError::UnknownScheme)
        );
        let salt = "ab".repeat(16);
        assert_eq!(
            import(sha2_input("sha1", Some(&salt))),
            Err(HashPolicyError::WeakParameters)
        );
        assert_eq!(
            import(
                serde_json::json!({"scheme": "django_pbkdf2", "hash": "unsalted_sha1$$5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"})
            ),
            Err(HashPolicyError::UnknownScheme)
        );
    }

    #[test]
    fn import_refuses_over_cap_argon2_phc() {
        assert_eq!(
            import(serde_json::json!({"scheme": "argon2", "hash": argon2(4_194_304, 2, 1)})),
            Err(HashPolicyError::OverCap)
        );
        assert_eq!(
            import(serde_json::json!({"scheme": "argon2", "hash": argon2(19456, 11, 1)})),
            Err(HashPolicyError::OverCap)
        );
        // The other caps at import too.
        assert_eq!(
            import(
                serde_json::json!({"scheme": "bcrypt", "hash": format!("$2b$17${BCRYPT_TAIL}")})
            ),
            Err(HashPolicyError::OverCap)
        );
        assert_eq!(
            import(pbkdf2_input(5_000_001, 16)),
            Err(HashPolicyError::OverCap)
        );
        assert_eq!(
            import(serde_json::json!({
                "scheme": "scrypt", "salt": {"hex": "abab"}, "hash": {"hex": "cd".repeat(32)},
                "log_n": 17, "r": 8, "p": 1
            })),
            Err(HashPolicyError::OverCap)
        );
        assert_eq!(
            import(serde_json::json!({
                "scheme": "scrypt", "salt": {"hex": "abab"}, "hash": {"hex": "cd".repeat(32)},
                "log_n": 0, "r": 8, "p": 1
            })),
            Err(HashPolicyError::Malformed)
        );
    }

    #[test]
    fn import_rejects_unknown_fields() {
        let extra = serde_json::json!({"scheme": "argon2", "hash": ARGON2I_README, "pepper": "x"});
        assert!(serde_json::from_value::<ImportPassword>(extra.clone()).is_err());
        assert_eq!(
            parse_import_value(extra).err(),
            Some(HashPolicyError::Malformed)
        );
        let both = serde_json::json!({
            "scheme": "pbkdf2", "prf": "sha256", "iterations": 600000,
            "salt": {"hex": "abababababababab", "base64": "q6urq6urq6s="}, "hash": {"hex": "cd".repeat(32)}
        });
        assert_eq!(
            parse_import_value(both).err(),
            Some(HashPolicyError::Malformed)
        );
        for bad in [
            serde_json::json!({"hash": ARGON2I_README}),
            serde_json::json!({"scheme": 7}),
            serde_json::json!("bcrypt"),
            serde_json::json!({"scheme": "pbkdf2", "prf": "md5", "iterations": 1000,
                "salt": {"hex": "abababababababab"}, "hash": {"hex": "cd"}}),
            serde_json::json!({"scheme": "scrypt", "salt": {"hex": "ab"}, "hash": {"hex": "cd"},
                "log_n": 300, "r": 8, "p": 1}),
        ] {
            assert_eq!(
                parse_import_value(bad.clone()).err(),
                Some(HashPolicyError::Malformed),
                "{bad}"
            );
        }
        // Bad hex / base64 in a byte field.
        for salt in [
            serde_json::json!({"hex": "abc"}),
            serde_json::json!({"hex": "zz"}),
            serde_json::json!({"base64": "q6u-"}),
        ] {
            let mut v = pbkdf2_input(600_000, 16);
            v["salt"] = salt;
            assert_eq!(import(v), Err(HashPolicyError::Malformed));
        }
    }

    #[test]
    fn import_password_debug_redacts() {
        let inputs = [
            serde_json::json!({"scheme": "bcrypt", "hash": format!("$2b$10${BCRYPT_TAIL}")}),
            serde_json::json!({"scheme": "argon2", "hash": ARGON2I_README}),
            serde_json::json!({
                "scheme": "firebase_scrypt", "salt": {"base64": FIREBASE_SALT}, "hash": {"base64": FIREBASE_HASH},
                "profile": "0b9a6b7e-1c2d-4e3f-8a9b-0c1d2e3f4a5b"
            }),
            serde_json::json!({
                "scheme": "scrypt", "salt": {"base64": "TmFDbA=="}, "hash": {"hex": RFC7914_HASH},
                "log_n": 10, "r": 8, "p": 16
            }),
            serde_json::json!({
                "scheme": "django_pbkdf2",
                "hash": "pbkdf2_sha256$600000$seasalt2026abcdefghij$vzhv8lHKtIQgPgn8kaqzhwkhLxdlkVYL69D6MdJ5Hz4="
            }),
            sha2_input("sha256", Some("00112233445566778899aabbccddeeff")),
        ];
        for v in inputs {
            let p = parse_import_value(v).unwrap();
            let out = format!("{p:?}");
            assert!(out.contains(p.scheme()), "{out}");
            for needle in [
                "E5YPO9kmyu",
                "c29tZXNhbHQ",
                "42xEC",
                "lSrfV15",
                "TmFDbA",
                "fdbabe1c",
                "seasalt",
                "vzhv8l",
                "00112233",
                "cdcdcd",
            ] {
                assert!(!out.contains(needle), "{out:?} leaks {needle:?}");
            }
            let c = convert_import(&p).unwrap();
            let out = format!("{c:?}");
            assert!(!out.contains('$') && out.contains("stored_len"), "{out}");
        }
    }

    proptest! {
        #[test]
        fn import_conversion_is_total(raw in proptest::collection::vec(any::<u8>(), 0..300)) {
            if let Ok(p) = serde_json::from_slice::<ImportPassword>(&raw) {
                if let Ok(c) = convert_import(&p) {
                    let h = parse_stored(&c.stored).expect("converted output parses");
                    prop_assert_eq!(check_stored_caps(&h), Ok(()));
                }
            }
        }

        #[test]
        fn converted_output_always_parses(
            ln in 1u8..=16, r in 1u32..=8, salt in proptest::collection::vec(any::<u8>(), 1..64),
            hash in proptest::collection::vec(any::<u8>(), 16..=64)
        ) {
            let v = serde_json::json!({
                "scheme": "scrypt", "salt": {"base64": anvil_jose::encoding::b64std(&salt)},
                "hash": {"base64": anvil_jose::encoding::b64std(&hash)}, "log_n": ln, "r": r, "p": 1
            });
            let c = import(v).expect("in range");
            let parsed = parse_stored(&c.stored).unwrap();
            prop_assert_eq!(parsed, StoredHash::Scrypt { log_n: ln, r, p: 1, salt, hash });
        }
    }
}
