//! Tenant password hash profiles for imported hashes (ADM-08).
//!
//! A profile holds the parameters an imported legacy hash needs besides the per-user salt and
//! hash. Today the only kind is Firebase Authentication's modified scrypt: signer key, salt
//! separator, rounds and memory cost. Imported Firebase hashes reference the profile by id
//! (`$anvil-firebase-scrypt$profile=<uuid>$…`, see `policy::password_import`).
//!
//! The signer key is a secret. [`HashProfileService::create`] seals it with the KEK (purpose
//! [`PROFILE_SIGNER_KEY_PURPOSE`], AAD [`profile_signer_key_aad`] = tenant id ‖ profile id) and
//! stores only the sealed blob. Nothing returned by this service carries the key or the sealed
//! blob: [`HashProfileSummary`] lists the public parameters only. [`HashProfileService::material_for`]
//! unseals the key for the one consumer that needs it, password verification at sign-in.
//!
//! Deleting a profile that stored credentials still reference is refused with `Conflict`
//! (verification of those users would fail closed). Creation and deletion are audited
//! (`password_profile_created`, `password_profile_deleted`; target = profile id, details = name
//! and kind only).

use std::sync::Arc;

use anvil_jose::Kek;
use secrecy::{ExposeSecret as _, SecretBox};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, HashProfileMaterial,
    NewPasswordHashProfile, PROFILE_SIGNER_KEY_PURPOSE, PasswordHashProfile, ProfileKind,
    RequestContext, TenantId, profile_signer_key_aad,
};
use crate::policy::password_import::check_scrypt_params;
use crate::ports::{Storage, StorageError};
use crate::service::audit::AuditService;

/// Longest profile name in characters.
pub const MAX_PROFILE_NAME_LEN: usize = 64;
/// Largest accepted signer key in bytes (Firebase keys are 64 bytes).
pub const MAX_SIGNER_KEY_BYTES: usize = 256;
/// Largest accepted salt separator in bytes (Firebase separators are 1 byte).
pub const MAX_SALT_SEPARATOR_BYTES: usize = 64;

/// Input of [`HashProfileService::create`]. `Debug` never prints the signer key.
#[derive(Debug)]
pub struct NewHashProfile {
    pub name: String,
    pub kind: ProfileKind,
    /// The raw signer key bytes (Firebase `base64_signer_key`, decoded).
    pub signer_key: SecretBox<[u8]>,
    /// The raw salt separator bytes (Firebase `base64_salt_separator`, decoded).
    pub salt_separator: Vec<u8>,
    pub rounds: u32,
    pub mem_cost: u8,
}

/// A profile as shown to administrators: public parameters only, never the signer key or its
/// sealed form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashProfileSummary {
    pub id: Uuid,
    pub name: String,
    pub kind: ProfileKind,
    pub salt_separator: Vec<u8>,
    pub rounds: u32,
    pub mem_cost: u8,
    pub created_at: OffsetDateTime,
}

impl From<PasswordHashProfile> for HashProfileSummary {
    fn from(p: PasswordHashProfile) -> Self {
        Self {
            id: p.id,
            name: p.name,
            kind: p.kind,
            salt_separator: p.salt_separator,
            rounds: p.rounds,
            mem_cost: p.mem_cost,
            created_at: p.created_at,
        }
    }
}

fn invalid(field: &'static str, message: &str) -> CoreError {
    CoreError::Validation {
        field,
        message: message.to_owned(),
    }
}

/// Validates the parameters of a new profile (pure).
pub fn check_new_profile(input: &NewHashProfile) -> Result<String, CoreError> {
    let name = input.name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_PROFILE_NAME_LEN
        || name.chars().any(char::is_control)
    {
        return Err(invalid(
            "name",
            "must be 1-64 characters without control characters",
        ));
    }
    let key = input.signer_key.expose_secret();
    if key.is_empty() || key.len() > MAX_SIGNER_KEY_BYTES {
        return Err(invalid("signer_key", "must be 1-256 bytes"));
    }
    if input.salt_separator.len() > MAX_SALT_SEPARATOR_BYTES {
        return Err(invalid("salt_separator", "must be at most 64 bytes"));
    }
    match input.kind {
        ProfileKind::FirebaseScrypt => {
            if input.rounds == 0 || input.mem_cost == 0 {
                return Err(invalid("rounds", "rounds and mem_cost must be at least 1"));
            }
            // Same memory cap as imported scrypt hashes (p = 1 for Firebase).
            check_scrypt_params(input.mem_cost, input.rounds, 1).map_err(|e| {
                invalid(
                    "mem_cost",
                    &format!("scrypt parameters refused: {}", e.reason()),
                )
            })?;
        }
    }
    Ok(name.to_owned())
}

/// Seals a signer key for `profile` in `tenant`.
pub fn seal_signer_key(
    kek: &Kek,
    tenant: TenantId,
    profile: Uuid,
    key: &[u8],
) -> Result<Vec<u8>, CoreError> {
    kek.seal(
        PROFILE_SIGNER_KEY_PURPOSE,
        &profile_signer_key_aad(tenant, profile),
        key,
    )
    .map_err(|_| CoreError::Internal("sealing the profile signer key failed".into()))
}

/// Opens a sealed signer key; fails when the blob belongs to another tenant or profile.
pub fn open_signer_key(
    kek: &Kek,
    tenant: TenantId,
    profile: Uuid,
    sealed: &[u8],
) -> Result<SecretBox<[u8]>, CoreError> {
    let opened = kek
        .open(
            PROFILE_SIGNER_KEY_PURPOSE,
            &profile_signer_key_aad(tenant, profile),
            sealed,
        )
        .map_err(|_| CoreError::Internal("the profile signer key does not open".into()))?;
    Ok(SecretBox::from(opened.to_vec().into_boxed_slice()))
}

/// Hash profile management and the unsealing of profile material for verification.
pub struct HashProfileService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub kek: Arc<Kek>,
}

impl HashProfileService {
    async fn audit(
        &self,
        tenant: TenantId,
        actor: AuditActor,
        action: AuditAction,
        profile: &PasswordHashProfile,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let details = AuditDetails::from_stored(serde_json::Map::from_iter([
            (
                "name".to_owned(),
                serde_json::Value::from(profile.name.clone()),
            ),
            (
                "kind".to_owned(),
                serde_json::Value::from(profile.kind.as_str()),
            ),
        ]));
        AuditService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
        }
        .record(
            tenant,
            actor,
            action,
            Some(profile.id.to_string()),
            AuditOutcome::Success,
            ctx,
            details,
        )
        .await
    }

    /// Creates a profile with a sealed signer key. `Conflict` if the name is taken in the
    /// tenant. Audited `password_profile_created`.
    pub async fn create(
        &self,
        tenant: TenantId,
        input: NewHashProfile,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<HashProfileSummary, CoreError> {
        let name = check_new_profile(&input)?;
        let id = Uuid::now_v7();
        let sealed = seal_signer_key(&self.kek, tenant, id, input.signer_key.expose_secret())?;
        let new = NewPasswordHashProfile {
            id,
            name,
            kind: input.kind,
            salt_separator: input.salt_separator,
            rounds: input.rounds,
            mem_cost: input.mem_cost,
            signer_key_sealed: sealed,
            created_at: self.clock.now(),
        };
        let stored = self
            .storage
            .password_profiles()
            .create(tenant, &new)
            .await
            .map_err(|e| match e {
                StorageError::Conflict(_) => {
                    CoreError::Conflict("a hash profile with this name already exists".into())
                }
                other => other.into(),
            })?;
        self.audit(
            tenant,
            actor,
            AuditAction::PasswordProfileCreated,
            &stored,
            ctx,
        )
        .await?;
        Ok(stored.into())
    }

    /// Every profile of the tenant, in name order (no key material).
    pub async fn list(&self, tenant: TenantId) -> Result<Vec<HashProfileSummary>, CoreError> {
        Ok(self
            .storage
            .password_profiles()
            .list(tenant)
            .await?
            .into_iter()
            .map(HashProfileSummary::from)
            .collect())
    }

    /// One profile (`NotFound` if unknown in the tenant; no key material).
    pub async fn get(&self, tenant: TenantId, id: Uuid) -> Result<HashProfileSummary, CoreError> {
        self.storage
            .password_profiles()
            .get(tenant, id)
            .await?
            .map(HashProfileSummary::from)
            .ok_or(CoreError::NotFound)
    }

    /// Whether the profile exists in the tenant.
    pub async fn exists(&self, tenant: TenantId, id: Uuid) -> Result<bool, CoreError> {
        Ok(self
            .storage
            .password_profiles()
            .get(tenant, id)
            .await?
            .is_some())
    }

    /// Deletes a profile. `NotFound` if unknown; `Conflict` while stored credentials reference
    /// it. Audited `password_profile_deleted`.
    pub async fn delete(
        &self,
        tenant: TenantId,
        id: Uuid,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        let repo = self.storage.password_profiles();
        let profile = repo.get(tenant, id).await?.ok_or(CoreError::NotFound)?;
        let refs = repo.count_references(tenant, id).await?;
        if refs > 0 {
            return Err(CoreError::Conflict(format!(
                "the hash profile is referenced by {refs} password credential(s)"
            )));
        }
        if !repo.delete(tenant, id).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(
            tenant,
            actor,
            AuditAction::PasswordProfileDeleted,
            &profile,
            ctx,
        )
        .await
    }

    /// The unsealed parameters of a profile, for password verification only. `Ok(None)` if the
    /// profile does not exist in the tenant; `Internal` if the sealed key does not open (wrong
    /// KEK, or a blob copied from another profile or tenant).
    pub async fn material_for(
        &self,
        tenant: TenantId,
        id: Uuid,
    ) -> Result<Option<HashProfileMaterial>, CoreError> {
        let Some(p) = self.storage.password_profiles().get(tenant, id).await? else {
            return Ok(None);
        };
        let signer_key = open_signer_key(&self.kek, tenant, p.id, &p.signer_key_sealed)?;
        Ok(Some(HashProfileMaterial {
            salt_separator: p.salt_separator,
            signer_key,
            rounds: p.rounds,
            mem_cost: p.mem_cost,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> NewHashProfile {
        NewHashProfile {
            name: "firebase".into(),
            kind: ProfileKind::FirebaseScrypt,
            signer_key: SecretBox::from(vec![0x5A_u8; 64].into_boxed_slice()),
            salt_separator: vec![0x07],
            rounds: 8,
            mem_cost: 14,
        }
    }

    #[test]
    fn profile_signer_key_aad_bound() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let profile = Uuid::now_v7();
        let key = [0x5A_u8; 64];
        let sealed = seal_signer_key(&kek, tenant, profile, &key).unwrap();
        // The stored blob is not the key and does not contain it.
        assert_ne!(sealed.as_slice(), key.as_slice());
        assert!(!sealed.windows(16).any(|w| w == &key[..16]));
        // Opens with the right tenant + profile only.
        let opened = open_signer_key(&kek, tenant, profile, &sealed).unwrap();
        assert_eq!(opened.expose_secret(), key.as_slice());
        assert!(open_signer_key(&kek, tenant, Uuid::now_v7(), &sealed).is_err());
        assert!(open_signer_key(&kek, TenantId::new_v7(), profile, &sealed).is_err());
        assert!(open_signer_key(&Kek::generate(), tenant, profile, &sealed).is_err());
    }

    #[test]
    fn new_profile_validation() {
        assert_eq!(check_new_profile(&input()).unwrap(), "firebase");
        let mut i = input();
        i.name = " ".into();
        assert!(matches!(
            check_new_profile(&i),
            Err(CoreError::Validation { field: "name", .. })
        ));
        let mut i = input();
        i.signer_key = SecretBox::from(Vec::new().into_boxed_slice());
        assert!(matches!(
            check_new_profile(&i),
            Err(CoreError::Validation {
                field: "signer_key",
                ..
            })
        ));
        // 128 * 2^20 * 8 bytes = 1 GiB: over the scrypt memory cap.
        let mut i = input();
        i.mem_cost = 20;
        assert!(matches!(
            check_new_profile(&i),
            Err(CoreError::Validation {
                field: "mem_cost",
                ..
            })
        ));
        let mut i = input();
        i.rounds = 0;
        assert!(check_new_profile(&i).is_err());
        let mut i = input();
        i.salt_separator = vec![0; 65];
        assert!(check_new_profile(&i).is_err());
    }

    #[test]
    fn new_profile_debug_redacts_the_signer_key() {
        let dbg = format!("{:?}", input());
        assert!(!dbg.contains("90, 90"), "{dbg}");
        assert!(!dbg.contains("5a"), "{dbg}");
    }
}
