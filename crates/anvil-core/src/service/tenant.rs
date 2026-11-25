//! Tenant management and signing-key sealing.
//!
//! [`seal_new_key`] is the single place where a new signing key is generated and sealed with the
//! KEK. Bootstrap, tenant creation and key rotation all go through it.

use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::keys::Alg;
use time::OffsetDateTime;

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    DEFAULT_TENANT_SLUG, KeyState, NewSigningKey, NewTenant, Page, PageRequest,
    SIGNING_KEY_PURPOSE, SYSTEM_TENANT_SLUG, SigningKeyId, Tenant, TenantId, TenantSettings,
    TenantUpdate, signing_key_aad,
};
use crate::ports::{Storage, StorageError};

/// Default page size for management listings.
pub const DEFAULT_PAGE_LIMIT: u32 = 50;

/// Maximum length of a display name in characters.
pub const MAX_DISPLAY_NAME_LEN: usize = 200;

/// Normalises a management-API page request: `limit == 0` means the default (50); any other
/// limit is clamped to `1..=200`. Shared by the tenant, client and user services.
pub fn admin_page(page: PageRequest) -> PageRequest {
    let limit = if page.limit == 0 {
        DEFAULT_PAGE_LIMIT
    } else {
        page.clamped_limit()
    };
    PageRequest {
        after: page.after,
        limit,
    }
}

/// Generates an RS256 key and seals it: [`seal_new_key_for`] with [`Alg::RS256`]. Bootstrap,
/// installation and the test harness use this.
pub fn seal_new_key(
    kek: &Kek,
    tenant: TenantId,
    now: OffsetDateTime,
    state: KeyState,
) -> Result<NewSigningKey, CoreError> {
    seal_new_key_for(kek, tenant, Alg::RS256, now, state)
}

/// Generates a key for `alg` and seals its PKCS#8 private key with the KEK (purpose
/// [`SIGNING_KEY_PURPOSE`], AAD [`signing_key_aad`] of the new row id). The kid is the RFC 7638
/// thumbprint of the public JWK. `activated_at` is set when `state` is `Active`.
///
/// `tenant` is the tenant the caller will insert the key for; the sealed envelope is bound to
/// the key row id, which is unique across tenants.
pub fn seal_new_key_for(
    kek: &Kek,
    tenant: TenantId,
    alg: Alg,
    now: OffsetDateTime,
    state: KeyState,
) -> Result<NewSigningKey, CoreError> {
    let _ = tenant;
    let generated = anvil_jose::generate(alg)
        .map_err(|e| CoreError::Internal(format!("signing key generation failed: {e}")))?;
    let id = SigningKeyId::new_v7();
    let private_key_enc = kek
        .seal(SIGNING_KEY_PURPOSE, &signing_key_aad(id), &generated.pkcs8)
        .map_err(|e| CoreError::Internal(format!("signing key sealing failed: {e}")))?;
    let public_jwk = serde_json::to_string(&generated.public_jwk)
        .map_err(|e| CoreError::Internal(format!("public JWK serialisation failed: {e}")))?;
    Ok(NewSigningKey {
        id,
        kid: generated.kid,
        alg: generated.alg.as_str().to_owned(),
        state,
        private_key_enc,
        public_jwk,
        created_at: now,
        activated_at: (state == KeyState::Active).then_some(now),
        retired_at: None,
        expires_at: None,
    })
}

fn validation(field: &'static str, message: &str) -> CoreError {
    CoreError::Validation {
        field,
        message: message.to_owned(),
    }
}

/// Whether `slug` is one of the bootstrap tenants (`system`, `default`).
pub fn is_protected_slug(slug: &str) -> bool {
    slug == SYSTEM_TENANT_SLUG || slug == DEFAULT_TENANT_SLUG
}

/// Slug syntax: `^[a-z0-9][a-z0-9-]{1,62}$`.
pub fn validate_slug(slug: &str) -> Result<(), CoreError> {
    let bytes = slug.as_bytes();
    let ok = (2..=63).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    if ok {
        Ok(())
    } else {
        Err(validation(
            "slug",
            "must be 2-63 characters of a-z, 0-9 and '-', starting with a letter or digit",
        ))
    }
}

/// Slug rules for a tenant created through the management API: syntax plus the reserved
/// bootstrap slugs.
pub fn validate_new_slug(slug: &str) -> Result<(), CoreError> {
    validate_slug(slug)?;
    if is_protected_slug(slug) {
        return Err(validation("slug", "is reserved"));
    }
    Ok(())
}

fn validate_display_name(name: &str) -> Result<String, CoreError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(validation("display_name", "is required"));
    }
    if name.chars().count() > MAX_DISPLAY_NAME_LEN || name.chars().any(char::is_control) {
        return Err(validation(
            "display_name",
            "must be at most 200 characters without control characters",
        ));
    }
    Ok(name.to_owned())
}

/// Custom host: a lowercase DNS name with an optional port, no scheme or path.
fn validate_host(host: &str) -> Result<String, CoreError> {
    let host = host.trim().to_ascii_lowercase();
    let (name, port) = match host.split_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (host.as_str(), None),
    };
    let name_ok = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    let port_ok = port.is_none_or(|p| {
        !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().is_ok_and(|n| n > 0)
    });
    if name_ok && port_ok {
        Ok(host)
    } else {
        Err(validation(
            "host",
            "must be a DNS host name with an optional port, without scheme or path",
        ))
    }
}

fn map_conflict(e: StorageError) -> CoreError {
    match e {
        StorageError::Conflict(_) => CoreError::Conflict("slug or host already in use".to_owned()),
        other => other.into(),
    }
}

/// Input for [`TenantService::create`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTenantInput {
    pub slug: String,
    pub display_name: String,
    pub host: Option<String>,
    pub settings: TenantSettings,
}

/// Partial tenant update. Slugs are immutable for every tenant (issuers derive from them), so
/// there is no slug field. `host: Some(None)` clears the custom host.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TenantPatch {
    pub display_name: Option<String>,
    pub host: Option<Option<String>>,
    pub settings: Option<TenantSettings>,
}

/// Tenant management.
pub struct TenantService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub kek: Arc<Kek>,
}

impl TenantService {
    /// Creates a tenant and its active RS256 signing key.
    ///
    /// This is a two-step write (tenant, then key) rather than one transaction. That is
    /// acceptable: a tenant without a key cannot issue tokens and is unusable, and if the key
    /// insert fails the tenant is deleted again before the error is returned.
    pub async fn create(&self, input: NewTenantInput) -> Result<Tenant, CoreError> {
        validate_new_slug(&input.slug)?;
        let display_name = validate_display_name(&input.display_name)?;
        let host = input.host.as_deref().map(validate_host).transpose()?;
        let now = self.clock.now();
        let new = NewTenant {
            id: TenantId::new_v7(),
            slug: input.slug,
            display_name,
            host,
            settings: input.settings,
            created_at: now,
        };
        // Generate the key before writing anything so a crypto failure leaves no tenant behind.
        let key = seal_new_key(&self.kek, new.id, now, KeyState::Active)?;
        let tenant = self
            .storage
            .tenants()
            .create(&new)
            .await
            .map_err(map_conflict)?;
        if let Err(e) = self.storage.keys().insert(tenant.id, &key).await {
            // Compensate; the original failure is what the caller needs to see.
            let _ = self.storage.tenants().delete(tenant.id).await;
            return Err(CoreError::Internal(format!(
                "signing key insert failed for new tenant: {e}"
            )));
        }
        Ok(tenant)
    }

    pub async fn get(&self, slug: &str) -> Result<Tenant, CoreError> {
        self.storage
            .tenants()
            .get_by_slug(slug)
            .await?
            .ok_or(CoreError::NotFound)
    }

    pub async fn list(&self, page: PageRequest) -> Result<Page<Tenant>, CoreError> {
        Ok(self.storage.tenants().list(admin_page(page)).await?)
    }

    pub async fn update(&self, slug: &str, patch: TenantPatch) -> Result<Tenant, CoreError> {
        let tenant = self.get(slug).await?;
        let update = TenantUpdate {
            display_name: patch
                .display_name
                .as_deref()
                .map(validate_display_name)
                .transpose()?,
            host: match patch.host {
                None => None,
                Some(None) => Some(None),
                Some(Some(h)) => Some(Some(validate_host(&h)?)),
            },
            settings: patch.settings,
        };
        self.storage
            .tenants()
            .update(tenant.id, &update)
            .await
            .map_err(map_conflict)?
            .ok_or(CoreError::NotFound)
    }

    /// Deletes a tenant and everything in it. The bootstrap tenants are `Forbidden`.
    pub async fn delete(&self, slug: &str) -> Result<(), CoreError> {
        if is_protected_slug(slug) {
            return Err(CoreError::Forbidden);
        }
        let tenant = self.get(slug).await?;
        if self.storage.tenants().delete(tenant.id).await? {
            Ok(())
        } else {
            Err(CoreError::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anvil_jose::{Alg, Jwk, SigningKey, thumbprint};

    #[test]
    fn seal_new_key_for_produces_es256_and_ed25519_keys() {
        let kek = Kek::generate();
        let now = OffsetDateTime::UNIX_EPOCH;
        for alg in [Alg::ES256, Alg::Ed25519] {
            let key = seal_new_key_for(&kek, TenantId::new_v7(), alg, now, KeyState::Next).unwrap();
            assert_eq!(key.alg, alg.as_str());
            assert!(key.activated_at.is_none());
            let jwk: Jwk = serde_json::from_str(&key.public_jwk).unwrap();
            assert_eq!(key.kid, thumbprint(&jwk).unwrap());
            assert_eq!(jwk.alg.as_deref(), Some(alg.as_str()));
            let pkcs8 = kek
                .open(
                    SIGNING_KEY_PURPOSE,
                    &signing_key_aad(key.id),
                    &key.private_key_enc,
                )
                .unwrap();
            let signer = SigningKey::from_pkcs8(&key.kid, alg, &pkcs8).unwrap();
            assert_eq!(signer.alg(), alg);
        }
    }

    #[test]
    fn seal_new_key_produces_a_sealed_rs256_key() {
        let kek = Kek::generate();
        let now = OffsetDateTime::UNIX_EPOCH;
        for state in [KeyState::Active, KeyState::Next] {
            let key = seal_new_key(&kek, TenantId::new_v7(), now, state).unwrap();
            assert_eq!(key.state, state);
            assert_eq!(key.alg, "RS256");
            assert_eq!(key.created_at, now);
            assert_eq!(key.activated_at.is_some(), state == KeyState::Active);
            let jwk: Jwk = serde_json::from_str(&key.public_jwk).unwrap();
            assert_eq!(key.kid, thumbprint(&jwk).unwrap());
            assert_eq!(jwk.kid.as_deref(), Some(key.kid.as_str()));
            let pkcs8 = kek
                .open(
                    SIGNING_KEY_PURPOSE,
                    &signing_key_aad(key.id),
                    &key.private_key_enc,
                )
                .unwrap();
            SigningKey::from_pkcs8(&key.kid, Alg::RS256, &pkcs8).unwrap();
            // Bound to its row id: another id's AAD does not open it.
            assert!(
                kek.open(
                    SIGNING_KEY_PURPOSE,
                    &signing_key_aad(SigningKeyId::new_v7()),
                    &key.private_key_enc
                )
                .is_err()
            );
        }
    }

    #[test]
    fn slug_validation() {
        let too_long = "a".repeat(64);
        for bad in [
            "Acme",
            "-x",
            "a",
            "",
            "ac me",
            "acme_1",
            "äcme",
            too_long.as_str(),
        ] {
            assert!(
                matches!(
                    validate_slug(bad),
                    Err(CoreError::Validation { field: "slug", .. })
                ),
                "{bad:?} must be rejected"
            );
        }
        let max = "a".repeat(63);
        for good in ["acme-1", "ab", "0x", "a-", max.as_str()] {
            assert!(validate_slug(good).is_ok(), "{good:?} must be accepted");
        }
    }

    #[test]
    fn reserved_slugs_are_rejected_for_create() {
        for reserved in ["system", "default"] {
            assert!(validate_slug(reserved).is_ok());
            assert!(matches!(
                validate_new_slug(reserved),
                Err(CoreError::Validation { field: "slug", .. })
            ));
            assert!(is_protected_slug(reserved));
        }
        assert!(validate_new_slug("acme").is_ok());
        assert!(!is_protected_slug("acme"));
    }

    #[test]
    fn host_validation() {
        assert_eq!(validate_host("Login.Acme.com").unwrap(), "login.acme.com");
        assert_eq!(validate_host("id.example:8443").unwrap(), "id.example:8443");
        for bad in [
            "",
            "https://login.acme.com",
            "login.acme.com/path",
            "-a.example",
            "a..example",
            "a.example:0",
            "a.example:",
            "a.example:99999",
            "user@a.example",
        ] {
            assert!(validate_host(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn display_name_validation() {
        assert_eq!(validate_display_name("  Acme  ").unwrap(), "Acme");
        assert!(validate_display_name("   ").is_err());
        assert!(validate_display_name(&"x".repeat(201)).is_err());
        assert!(validate_display_name("a\u{0}b").is_err());
    }

    #[test]
    fn admin_page_defaults_and_clamps() {
        let p = |limit| admin_page(PageRequest { after: None, limit }).limit;
        assert_eq!(p(0), 50);
        assert_eq!(p(1), 1);
        assert_eq!(p(500), 200);
    }
}
