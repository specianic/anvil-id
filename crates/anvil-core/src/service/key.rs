//! Signing-key service: opens the tenant's active key for an algorithm with the KEK and assembles
//! the published JWKS. Key generation lives in the tenant service ([`seal_new_key_for`]), rotation
//! in [`key_rotation`](super::key_rotation).
//!
//! [`seal_new_key_for`]: super::tenant::seal_new_key_for

use std::sync::Arc;

use anvil_jose::Kek;
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
        open_key(&self.kek, &key)
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
