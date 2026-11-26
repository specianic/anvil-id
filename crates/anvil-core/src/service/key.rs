//! Signing-key service: opens the tenant's active key for an algorithm with the KEK and assembles
//! the published JWKS. Key generation lives in the tenant service ([`seal_new_key_for`]), rotation
//! in [`key_rotation`](super::key_rotation).
//!
//! [`seal_new_key_for`]: super::tenant::seal_new_key_for
//!
//! ## Signer cache (QUAL-05)
//!
//! Opening a key (HKDF + AES-GCM, then a PKCS#8 parse) on every token request is wasted work: the
//! result only depends on the sealed bytes, the row id (the AAD), the algorithm and the KEK. The
//! parsed signer is therefore kept in a process-wide, **content-addressed** cache private to this
//! module, keyed by `(tenant, alg, kid, row id, sha256(sealed bytes), KEK fingerprint)`.
//!
//! The active-key row is still read from storage on every request, so a rotation (including
//! `keys rotate --immediate`) or a deleted key takes effect on the very next request: a different
//! active row has a different key and simply misses. A different sealed blob can never hit another
//! key's entry, and a different KEK never hits an entry opened with another KEK, which also makes
//! the `static` safe across parallel tests. Inserting a tenant's signer for an algorithm drops any
//! older entry of the same tenant and algorithm (the retired key's material leaves memory), and the
//! whole map is bounded to [`SIGNER_CACHE_CAPACITY`] entries (cleared on overflow).

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use anvil_jose::Kek;
use anvil_jose::encoding::sha256;
use anvil_jose::jwk::Jwks;
use anvil_jose::keys::{Alg, SigningKey};

use crate::error::CoreError;
use crate::model::{self, SIGNING_KEY_PURPOSE, TenantId, signing_key_aad};
use crate::ports::{Clock, Storage};

/// The signing algorithm of access tokens (and the default for ID tokens).
pub const TOKEN_ALG: Alg = Alg::RS256;

/// Decrypts a stored key with the KEK (purpose [`SIGNING_KEY_PURPOSE`], AAD bound to the row id)
/// and loads it for signing. Any failure is an internal error: the details never leave the server.
pub fn open_key(kek: &Kek, key: &model::SigningKey) -> Result<SigningKey, CoreError> {
    let alg: Alg = key
        .alg
        .parse()
        .map_err(|_| CoreError::Internal(format!("signing key {} has unknown alg", key.kid)))?;
    let pkcs8 = kek
        .open(
            SIGNING_KEY_PURPOSE,
            &signing_key_aad(key.id),
            &key.private_key_enc,
        )
        .map_err(|_| CoreError::Internal(format!("signing key {} cannot be opened", key.kid)))?;
    SigningKey::from_pkcs8(&key.kid, alg, &pkcs8)
        .map_err(|_| CoreError::Internal(format!("signing key {} cannot be loaded", key.kid)))
}

/// Maximum number of cached signers (one per tenant and algorithm in practice).
pub const SIGNER_CACHE_CAPACITY: usize = 1024;

/// HKDF info of the KEK fingerprint that scopes cache entries to the KEK that opened them.
const KEK_FINGERPRINT_INFO: &str = "anvilid/signer-cache/kek-fingerprint/v1";

/// Everything [`open_key`]'s result depends on. The sealed bytes and the KEK enter as hashes.
#[derive(Clone, PartialEq, Eq, Hash)]
struct SignerCacheKey {
    tenant: TenantId,
    alg: String,
    kid: String,
    row: model::SigningKeyId,
    sealed: [u8; 32],
    kek: [u8; 32],
}

type SignerCache = RwLock<HashMap<SignerCacheKey, SigningKey>>;

fn signer_cache() -> &'static SignerCache {
    static SIGNERS: OnceLock<SignerCache> = OnceLock::new();
    SIGNERS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// A one-way fingerprint of the KEK (SHA-256 of a domain-separated HKDF output).
fn kek_fingerprint(kek: &Kek) -> [u8; 32] {
    sha256(kek.derive_key(KEK_FINGERPRINT_INFO).as_ref())
}

/// [`open_key`] through the signer cache. Returns the signer and whether it was a cache hit
/// (the flag is informational; callers that do not care ignore it).
fn open_key_cached(kek: &Kek, key: &model::SigningKey) -> Result<(SigningKey, bool), CoreError> {
    let cache_key = SignerCacheKey {
        tenant: key.tenant_id,
        alg: key.alg.clone(),
        kid: key.kid.clone(),
        row: key.id,
        sealed: sha256(&key.private_key_enc),
        kek: kek_fingerprint(kek),
    };
    // A poisoned lock only means another thread panicked mid-operation on a plain map; the map
    // itself is still consistent, so keep using it.
    if let Some(hit) = signer_cache()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&cache_key)
    {
        return Ok((hit.clone(), true));
    }
    let signer = open_key(kek, key)?;
    insert_bounded(
        &mut signer_cache()
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        cache_key,
        signer.clone(),
        SIGNER_CACHE_CAPACITY,
    );
    Ok((signer, false))
}

/// Inserts a freshly opened signer: older entries of the same tenant and algorithm (a rotated or
/// deleted key) are dropped first, and a full map is cleared before inserting.
fn insert_bounded(
    map: &mut HashMap<SignerCacheKey, SigningKey>,
    key: SignerCacheKey,
    signer: SigningKey,
    capacity: usize,
) {
    map.retain(|k, _| !(k.tenant == key.tenant && k.alg == key.alg));
    if map.len() >= capacity {
        map.clear();
    }
    map.insert(key, signer);
}

/// Builds the JWK Set from stored key rows (their public JWKs, in row order).
pub fn jwks_from_rows(rows: &[model::SigningKey]) -> Result<Jwks, CoreError> {
    Jwks::from_public_jwks(rows.iter().map(|k| k.public_jwk.as_str()))
        .map_err(|_| CoreError::Internal("stored public JWK is invalid".to_owned()))
}

/// The tenant's published key set (next, active and not-yet-expired retired keys). Shared by
/// [`KeyService::jwks`] and access-token verification, which do not need the KEK.
pub async fn published_jwks(
    storage: &dyn Storage,
    clock: &dyn Clock,
    tenant: TenantId,
) -> Result<Jwks, CoreError> {
    let rows = storage.keys().published(tenant, clock.now()).await?;
    jwks_from_rows(&rows)
}

/// Signing and JWKS for one installation.
#[derive(Clone)]
pub struct KeyService {
    pub storage: Arc<dyn Storage>,
    pub kek: Arc<Kek>,
    pub clock: Arc<dyn Clock>,
}

impl KeyService {
    /// The tenant's active RS256 signing key (access tokens). No active key is an internal error.
    pub async fn signer(&self, tenant: TenantId) -> Result<SigningKey, CoreError> {
        self.signer_for(tenant, TOKEN_ALG).await
    }

    /// The tenant's active signing key for `alg`. No active key for that algorithm is an
    /// internal error: callers never fall back to another algorithm.
    pub async fn signer_for(&self, tenant: TenantId, alg: Alg) -> Result<SigningKey, CoreError> {
        let key = self
            .storage
            .keys()
            .active(tenant, alg.as_str())
            .await?
            .ok_or_else(|| {
                CoreError::Internal(format!("tenant has no active {} signing key", alg.as_str()))
            })?;
        open_key_cached(&self.kek, &key).map(|(signer, _hit)| signer)
    }

    /// The tenant's published JWK Set.
    pub async fn jwks(&self, tenant: TenantId) -> Result<Jwks, CoreError> {
        published_jwks(self.storage.as_ref(), self.clock.as_ref(), tenant).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{KeyState, SigningKeyId};
    use anvil_jose::generate_rs256;
    use anvil_jose::jws::{decode_header, verify_jwt};
    use time::OffsetDateTime;

    /// A stored key row sealed exactly like the tenant service does it.
    pub(crate) fn sealed_row(kek: &Kek, state: KeyState) -> model::SigningKey {
        let g = generate_rs256().unwrap();
        let id = SigningKeyId::new_v7();
        let enc = kek
            .seal(SIGNING_KEY_PURPOSE, &signing_key_aad(id), &g.pkcs8)
            .unwrap();
        model::SigningKey {
            id,
            tenant_id: TenantId::new_v7(),
            kid: g.kid.clone(),
            alg: "RS256".into(),
            state,
            private_key_enc: enc,
            public_jwk: serde_json::to_string(&g.public_jwk).unwrap(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            activated_at: None,
            retired_at: None,
            expires_at: None,
        }
    }

    #[test]
    fn sealed_key_opens_signs_and_verifies_against_rows_jwks() {
        let kek = Kek::generate();
        let active = sealed_row(&kek, KeyState::Active);
        let next = sealed_row(&kek, KeyState::Next);
        let signer = open_key(&kek, &active).unwrap();
        assert_eq!(signer.kid(), active.kid);

        let token = signer
            .sign_jwt(Some("at+jwt"), &serde_json::json!({"sub": "x"}))
            .unwrap();
        let header = decode_header(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some(active.kid.as_str()));

        let jwks = jwks_from_rows(&[next.clone(), active.clone()]).unwrap();
        assert_eq!(jwks.keys.len(), 2);
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid.as_deref() == header.kid.as_deref())
            .expect("header kid is published");
        assert_eq!(jwk.alg.as_deref(), Some("RS256"));
        verify_jwt(&token, &jwks, &[Alg::RS256]).unwrap();
    }

    #[test]
    fn wrong_kek_or_swapped_row_id_fails_closed() {
        let kek = Kek::generate();
        let row = sealed_row(&kek, KeyState::Active);
        assert!(matches!(
            open_key(&Kek::generate(), &row),
            Err(CoreError::Internal(_))
        ));
        let mut moved = row.clone();
        moved.id = SigningKeyId::new_v7();
        assert!(matches!(
            open_key(&kek, &moved),
            Err(CoreError::Internal(_))
        ));
    }

    fn cached_entries(tenant: TenantId) -> usize {
        signer_cache()
            .read()
            .unwrap()
            .keys()
            .filter(|k| k.tenant == tenant)
            .count()
    }

    #[test]
    fn second_open_of_the_same_row_is_a_cache_hit() {
        let kek = Kek::generate();
        let row = sealed_row(&kek, KeyState::Active);
        let (a, hit) = open_key_cached(&kek, &row).unwrap();
        assert!(!hit, "first open goes through the KEK");
        let (b, hit) = open_key_cached(&kek, &row).unwrap();
        assert!(hit, "second open is served from the cache");
        assert_eq!(a.kid(), b.kid());
        assert_eq!(cached_entries(row.tenant_id), 1);
        // The cached signer signs tokens that verify against the row's public key.
        let token = b.sign_jwt(None, &serde_json::json!({"sub": "x"})).unwrap();
        verify_jwt(&token, &jwks_from_rows(&[row]).unwrap(), &[Alg::RS256]).unwrap();
    }

    #[test]
    fn different_tenants_have_separate_entries() {
        let kek = Kek::generate();
        let one = sealed_row(&kek, KeyState::Active);
        let two = sealed_row(&kek, KeyState::Active);
        assert_ne!(one.tenant_id, two.tenant_id);
        open_key_cached(&kek, &one).unwrap();
        let (s, hit) = open_key_cached(&kek, &two).unwrap();
        assert!(!hit);
        assert_eq!(s.kid(), two.kid);
        assert_eq!(cached_entries(one.tenant_id), 1);
        assert_eq!(cached_entries(two.tenant_id), 1);
    }

    #[test]
    fn a_rotated_key_misses_and_evicts_the_old_entry() {
        let kek = Kek::generate();
        let old = sealed_row(&kek, KeyState::Active);
        let mut new = sealed_row(&kek, KeyState::Active);
        new.tenant_id = old.tenant_id;
        let (s, _) = open_key_cached(&kek, &old).unwrap();
        assert_eq!(s.kid(), old.kid);
        let (s, hit) = open_key_cached(&kek, &new).unwrap();
        assert!(!hit, "a new active row is never served from the old entry");
        assert_eq!(s.kid(), new.kid);
        assert_eq!(
            cached_entries(old.tenant_id),
            1,
            "the retired key's entry is dropped"
        );
        let (_, hit) = open_key_cached(&kek, &old).unwrap();
        assert!(!hit, "the old key is no longer cached");
    }

    #[test]
    fn content_addressing_rejects_a_swapped_blob_or_row_id() {
        let kek = Kek::generate();
        let row = sealed_row(&kek, KeyState::Active);
        open_key_cached(&kek, &row).unwrap();
        // Same tenant, kid and id, different sealed bytes (another key's blob): a miss, and the
        // AEAD then fails closed instead of the cached signer being returned.
        let mut swapped = row.clone();
        swapped.private_key_enc = sealed_row(&kek, KeyState::Active).private_key_enc;
        assert!(matches!(
            open_key_cached(&kek, &swapped),
            Err(CoreError::Internal(_))
        ));
        // Same blob under another row id (AAD): a miss and a failure, never a hit.
        let mut moved = row.clone();
        moved.id = SigningKeyId::new_v7();
        assert!(matches!(
            open_key_cached(&kek, &moved),
            Err(CoreError::Internal(_))
        ));
    }

    #[test]
    fn another_kek_never_hits_an_entry_opened_with_a_different_kek() {
        let kek = Kek::generate();
        let row = sealed_row(&kek, KeyState::Active);
        open_key_cached(&kek, &row).unwrap();
        assert!(matches!(
            open_key_cached(&Kek::generate(), &row),
            Err(CoreError::Internal(_))
        ));
    }

    #[test]
    fn the_cache_is_bounded() {
        let kek = Kek::generate();
        let signer = open_key(&kek, &sealed_row(&kek, KeyState::Active)).unwrap();
        let entry = |tenant: TenantId| SignerCacheKey {
            tenant,
            alg: "RS256".into(),
            kid: "k".into(),
            row: SigningKeyId::new_v7(),
            sealed: [0; 32],
            kek: [0; 32],
        };
        let mut map = HashMap::new();
        for _ in 0..4 {
            insert_bounded(&mut map, entry(TenantId::new_v7()), signer.clone(), 4);
        }
        assert_eq!(map.len(), 4);
        insert_bounded(&mut map, entry(TenantId::new_v7()), signer.clone(), 4);
        assert_eq!(map.len(), 1, "a full map is cleared before inserting");
        // Same tenant and alg replaces rather than grows.
        let t = TenantId::new_v7();
        insert_bounded(&mut map, entry(t), signer.clone(), 4);
        insert_bounded(&mut map, entry(t), signer, 4);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn rows_with_private_material_are_rejected() {
        let kek = Kek::generate();
        let mut row = sealed_row(&kek, KeyState::Active);
        row.public_jwk = r#"{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}"#.into();
        assert!(matches!(
            jwks_from_rows(&[row]),
            Err(CoreError::Internal(_))
        ));
    }
}
