//! Tenant management and signing-key sealing.
//!
//! [`seal_new_key`] is the single place where a new signing key is generated and sealed with the
//! KEK. Bootstrap, tenant creation and key rotation all go through it.
//!
//! Tenant settings: [`normalize_signing_algs`] accepts `RS256`, `ES256` and `Ed25519` and always
//! keeps RS256; enabling an algorithm generates its active key at once
//! ([`KeyRotationService::ensure_tenant`]). CAPTCHA secrets enter as plaintext
//! ([`CaptchaChange`]) and are stored sealed only ([`seal_captcha_secret`]).
//!
//! Every mutating [`TenantService`] method takes the acting administrator and the request context
//! and records exactly one audit event (`tenant_created`, `tenant_updated`, `tenant_deleted`) in
//! the **system** tenant (a deleted tenant's own log is gone with it), target = the tenant id.
//! Failed calls record nothing; details list changed field names, never values or secrets.

use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::b64url;
use anvil_jose::keys::Alg;
use secrecy::{ExposeSecret as _, SecretString};
use time::OffsetDateTime;

use crate::clock::Clock;
use crate::error::CoreError;
use crate::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, CAPTCHA_SECRET_PURPOSE, CaptchaProvider,
    CaptchaSettings, DEFAULT_SIGNING_ALG, DEFAULT_TENANT_SLUG, KeyState, NewSigningKey, NewTenant,
    Page, PageRequest, RequestContext, SIGNING_KEY_PURPOSE, SYSTEM_TENANT_SLUG, SigningKeyId,
    Tenant, TenantId, TenantSettings, TenantUpdate, signing_key_aad,
};
use crate::policy::claims_mapping::validate_mapping;
use crate::ports::{Storage, StorageError};
use crate::service::audit::AuditService;
use crate::service::key_rotation::{KeyRotationService, RotationPolicy};

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

/// Display name rules shared by tenants and connections: trimmed, 1-200 characters, no control
/// characters.
pub(crate) fn validate_display_name(name: &str) -> Result<String, CoreError> {
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
pub(crate) fn validate_host(host: &str) -> Result<String, CoreError> {
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

/// Signing algorithms a tenant may enable.
pub const SUPPORTED_SIGNING_ALGS: &[&str] = &["RS256", "ES256", "Ed25519"];

/// Validates and normalises a tenant's signing algorithms: each must be one of
/// [`SUPPORTED_SIGNING_ALGS`] (exact, case-sensitive); the result starts with RS256 (always
/// enabled) followed by the others in the given order, without duplicates.
pub fn normalize_signing_algs(algs: &[String]) -> Result<Vec<String>, CoreError> {
    let mut out = vec![DEFAULT_SIGNING_ALG.to_owned()];
    for alg in algs {
        if !SUPPORTED_SIGNING_ALGS.contains(&alg.as_str()) {
            return Err(CoreError::Validation {
                field: "signing_algs",
                message: format!(
                    "unsupported signing algorithm {alg:?} (use RS256, ES256 or Ed25519)"
                ),
            });
        }
        if !out.contains(alg) {
            out.push(alg.clone());
        }
    }
    Ok(out)
}

/// Maximum length of a CAPTCHA site key or secret.
pub const MAX_CAPTCHA_VALUE_LEN: usize = 512;

/// CAPTCHA configuration as an administrator supplies it (plaintext secret).
#[derive(Debug, Clone)]
pub struct CaptchaInput {
    pub provider: CaptchaProvider,
    pub site_key: String,
    pub secret: SecretString,
}

/// A CAPTCHA settings change.
#[derive(Debug, Clone)]
pub enum CaptchaChange {
    /// Enable (or replace) CAPTCHA; the secret is sealed before it is stored.
    Set(CaptchaInput),
    /// Disable CAPTCHA and drop the sealed secret.
    Clear,
}

/// Validates `input` and seals its secret with the KEK (purpose [`CAPTCHA_SECRET_PURPOSE`], AAD =
/// tenant id bytes, base64url), the form the CAPTCHA verifier opens.
pub fn seal_captcha_secret(
    kek: &Kek,
    tenant: TenantId,
    input: &CaptchaInput,
) -> Result<CaptchaSettings, CoreError> {
    let site_key = input.site_key.trim();
    let ok = |v: &str| {
        !v.is_empty()
            && v.chars().count() <= MAX_CAPTCHA_VALUE_LEN
            && !v.chars().any(|c| c.is_control() || c.is_whitespace())
    };
    if !ok(site_key) {
        return Err(validation(
            "captcha.site_key",
            "must be 1-512 characters without whitespace",
        ));
    }
    let secret = input.secret.expose_secret().trim();
    if !ok(secret) {
        return Err(validation(
            "captcha.secret",
            "must be 1-512 characters without whitespace",
        ));
    }
    let sealed = kek
        .seal(
            CAPTCHA_SECRET_PURPOSE,
            tenant.0.as_bytes(),
            secret.as_bytes(),
        )
        .map_err(|e| CoreError::Internal(format!("CAPTCHA secret sealing failed: {e}")))?;
    Ok(CaptchaSettings {
        provider: input.provider,
        site_key: site_key.to_owned(),
        secret_sealed: b64url(&sealed),
    })
}

/// Longest accepted `default_locale`.
pub const MAX_LOCALE_TAG_LEN: usize = 35;

/// BCP 47 language tag syntax as accepted for `default_locale`: a 2-3 letter language subtag
/// followed by `-`-separated subtags of 1-8 letters or digits (`en`, `de-DE`, `pt-BR`,
/// `zh-Hant-TW`). Pages fall back to the tenant default when no requested language matches; a
/// tag without a catalog falls back to English at render time.
pub fn validate_locale_tag(tag: &str) -> Result<(), CoreError> {
    let mut parts = tag.split('-');
    let lang_ok = parts
        .next()
        .is_some_and(|l| (2..=3).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_alphabetic()));
    let rest_ok =
        parts.all(|p| (1..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()));
    if tag.len() <= MAX_LOCALE_TAG_LEN && lang_ok && rest_ok {
        Ok(())
    } else {
        Err(validation(
            "default_locale",
            "must be a language tag such as en, de or pt-BR",
        ))
    }
}

/// Checks the 0.3 settings of `new` against `current` (`None` for a new tenant): the default
/// locale must be a language tag, and turning on `email_otp` or `magic_link` needs an SMTP
/// transport (`smtp_available`: the tenant's own SMTP settings or the installation SMTP).
/// Settings that are already on stay valid when SMTP goes away (sending then fails visibly in
/// the outbox), so unrelated updates are not blocked.
pub fn validate_phase4_settings(
    current: Option<&TenantSettings>,
    new: &TenantSettings,
    smtp_available: bool,
) -> Result<(), CoreError> {
    validate_locale_tag(&new.default_locale)?;
    let turned_on = |now: bool, before: Option<bool>| now && before != Some(true);
    if !smtp_available {
        if turned_on(new.email_otp, current.map(|c| c.email_otp)) {
            return Err(validation(
                "email_otp",
                "sign-in codes by email need SMTP: configure the tenant SMTP settings or the \
                 installation smtp_url first",
            ));
        }
        if turned_on(new.magic_link, current.map(|c| c.magic_link)) {
            return Err(validation(
                "magic_link",
                "magic links need SMTP: configure the tenant SMTP settings or the installation \
                 smtp_url first",
            ));
        }
    }
    Ok(())
}

/// The settings a tenant update stores: `requested` (if any) with normalised signing algorithms,
/// the current CAPTCHA settings carried over, then `captcha` applied. A sealed CAPTCHA value in
/// `requested` that differs from the current one is refused (secrets enter only as plaintext
/// through [`CaptchaChange`]). Returns `None` when nothing in the settings changes.
///
/// The 0.3 settings are checked with [`validate_phase4_settings`].
pub fn plan_settings(
    kek: &Kek,
    tenant: &Tenant,
    requested: Option<TenantSettings>,
    captcha: Option<&CaptchaChange>,
    smtp_available: bool,
) -> Result<Option<TenantSettings>, CoreError> {
    if requested.is_none() && captcha.is_none() {
        return Ok(None);
    }
    let mut settings = match requested {
        Some(mut s) => {
            if s.captcha.is_some() && s.captcha != tenant.settings.captcha {
                return Err(validation(
                    "captcha",
                    "set CAPTCHA with its plaintext secret, not a sealed value",
                ));
            }
            s.signing_algs = normalize_signing_algs(&s.signing_algs)?;
            validate_phase4_settings(Some(&tenant.settings), &s, smtp_available)?;
            s.captcha = tenant.settings.captcha.clone();
            s
        }
        None => tenant.settings.clone(),
    };
    match captcha {
        None => {}
        Some(CaptchaChange::Clear) => settings.captcha = None,
        Some(CaptchaChange::Set(input)) => {
            settings.captcha = Some(seal_captcha_secret(kek, tenant.id, input)?);
        }
    }
    Ok(Some(settings))
}

/// Client ids of `tenant` whose `id_token_signed_response_alg` is one of `algs`, in listing
/// order.
async fn clients_using_algs(
    storage: &dyn Storage,
    tenant: TenantId,
    algs: &[String],
) -> Result<Vec<String>, CoreError> {
    let mut out = Vec::new();
    let mut after = None;
    loop {
        let page = storage
            .clients()
            .list(tenant, PageRequest { after, limit: 200 })
            .await?;
        out.extend(
            page.items
                .into_iter()
                .filter(|c| {
                    c.id_token_signed_response_alg
                        .as_ref()
                        .is_some_and(|a| algs.contains(a))
                })
                .map(|c| c.client_id),
        );
        match page.next_cursor {
            Some(next) => after = Some(next),
            None => return Ok(out),
        }
    }
}

/// The conflict message for [`TenantService::update`] refusing to disable algorithms in use.
pub fn disabled_algs_in_use_message(algs: &[String], clients: &[String]) -> String {
    format!(
        "cannot disable signing algorithm(s) {} while clients use them for ID tokens: {} \
         (change id_token_signed_response_alg of these clients first)",
        algs.join(", "),
        clients.join(", ")
    )
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
    /// Whether the installation SMTP (`smtp_url`) is configured; enabling `email_otp` or
    /// `magic_link` needs it for a new tenant (which has no SMTP settings of its own yet).
    pub installation_smtp: bool,
}

/// Partial tenant update. Slugs are immutable for every tenant (issuers derive from them), so
/// there is no slug field. `host: Some(None)` clears the custom host.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TenantPatch {
    pub display_name: Option<String>,
    pub host: Option<Option<String>>,
    pub settings: Option<TenantSettings>,
    /// Whether the installation SMTP (`smtp_url`) is configured. Together with the tenant's own
    /// SMTP settings it decides whether `email_otp` / `magic_link` may be turned on.
    pub installation_smtp: bool,
}

/// Tenant management.
pub struct TenantService {
    pub storage: Arc<dyn Storage>,
    pub clock: Arc<dyn Clock>,
    pub kek: Arc<Kek>,
}

impl TenantService {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: self.storage.clone(),
            clock: self.clock.clone(),
        }
    }

    fn key_rotation(&self) -> KeyRotationService {
        KeyRotationService {
            storage: self.storage.clone(),
            kek: self.kek.clone(),
            clock: self.clock.clone(),
            policy: RotationPolicy::default(),
        }
    }

    /// Records a tenant event in the system tenant (target = the tenant id).
    async fn record(
        &self,
        actor: AuditActor,
        action: AuditAction,
        tenant: TenantId,
        ctx: &RequestContext,
        details: AuditDetails,
    ) -> Result<(), CoreError> {
        let system = self.get(SYSTEM_TENANT_SLUG).await.map_err(|e| match e {
            CoreError::NotFound => CoreError::Internal("the system tenant is missing".into()),
            other => other,
        })?;
        self.audit()
            .record(
                system.id,
                actor,
                action,
                Some(tenant.to_string()),
                AuditOutcome::Success,
                ctx,
                details,
            )
            .await
    }

    /// Creates a tenant and its active RS256 signing key, plus an active key for every other
    /// enabled algorithm. Audited as `tenant_created`.
    ///
    /// This is a two-step write (tenant, then key) rather than one transaction. That is
    /// acceptable: a tenant without a key cannot issue tokens and is unusable, and if the key
    /// insert fails the tenant is deleted again before the error is returned.
    pub async fn create(
        &self,
        input: NewTenantInput,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Tenant, CoreError> {
        validate_new_slug(&input.slug)?;
        let display_name = validate_display_name(&input.display_name)?;
        let host = input.host.as_deref().map(validate_host).transpose()?;
        let mut settings = input.settings;
        if settings.captcha.is_some() {
            return Err(validation(
                "captcha",
                "set CAPTCHA with its plaintext secret after the tenant exists",
            ));
        }
        settings.signing_algs = normalize_signing_algs(&settings.signing_algs)?;
        validate_phase4_settings(None, &settings, input.installation_smtp)?;
        // A new tenant has no attribute definitions yet.
        validate_mapping(&settings.claims, &[])?;
        let now = self.clock.now();
        let new = NewTenant {
            id: TenantId::new_v7(),
            slug: input.slug,
            display_name,
            host,
            settings,
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
        if tenant.settings.effective_signing_algs().len() > 1 {
            self.key_rotation().ensure_tenant(&tenant).await?;
        }
        self.record(
            actor,
            AuditAction::TenantCreated,
            tenant.id,
            ctx,
            AuditDetails::empty(),
        )
        .await?;
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

    /// Applies a patch and an optional CAPTCHA change ([`plan_settings`]). When settings change,
    /// every enabled signing algorithm gets an active key before this returns
    /// ([`KeyRotationService::ensure_tenant`]). Audited as `tenant_updated` with the changed
    /// field names.
    pub async fn update(
        &self,
        slug: &str,
        patch: TenantPatch,
        captcha: Option<CaptchaChange>,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<Tenant, CoreError> {
        let tenant = self.get(slug).await?;
        let mut fields: Vec<&'static str> = Vec::new();
        if patch.display_name.is_some() {
            fields.push("display_name");
        }
        if patch.host.is_some() {
            fields.push("host");
        }
        if patch.settings.is_some() {
            fields.push("settings");
        }
        if captcha.is_some() {
            fields.push("captcha");
        }
        let display_name = patch
            .display_name
            .as_deref()
            .map(validate_display_name)
            .transpose()?;
        let host = match patch.host {
            None => None,
            Some(None) => Some(None),
            Some(Some(h)) => Some(Some(validate_host(&h)?)),
        };
        let smtp_available = patch.installation_smtp
            || (patch.settings.is_some()
                && self
                    .storage
                    .mail_settings()
                    .smtp(tenant.id)
                    .await?
                    .is_some());
        let settings = plan_settings(
            &self.kek,
            &tenant,
            patch.settings,
            captcha.as_ref(),
            smtp_available,
        )?;
        if let Some(new) = &settings {
            self.refuse_disabling_used_algs(&tenant, new).await?;
            // Claim mapping is checked when it changes (stored configuration that predates a
            // rule never blocks unrelated updates; mapped_claims skips such rules at runtime).
            if new.claims != tenant.settings.claims {
                let attributes = self.storage.attributes().list(tenant.id).await?;
                validate_mapping(&new.claims, &attributes)?;
            }
        }
        let settings_changed = settings.is_some();
        let update = TenantUpdate {
            display_name,
            host,
            settings,
        };
        let updated = self
            .storage
            .tenants()
            .update(tenant.id, &update)
            .await
            .map_err(map_conflict)?
            .ok_or(CoreError::NotFound)?;
        if settings_changed {
            self.key_rotation().ensure_tenant(&updated).await?;
        }
        self.record(
            actor,
            AuditAction::TenantUpdated,
            updated.id,
            ctx,
            AuditDetails::fields(&fields),
        )
        .await?;
        Ok(updated)
    }

    /// Refuses settings that disable a signing algorithm which a client of the tenant still uses
    /// as its `id_token_signed_response_alg` (its token requests would fail otherwise):
    /// `Conflict` naming the algorithms and the affected client ids.
    async fn refuse_disabling_used_algs(
        &self,
        tenant: &Tenant,
        new: &TenantSettings,
    ) -> Result<(), CoreError> {
        let enabled = new.effective_signing_algs();
        let removed: Vec<String> = tenant
            .settings
            .effective_signing_algs()
            .into_iter()
            .filter(|a| !enabled.contains(a))
            .collect();
        if removed.is_empty() {
            return Ok(());
        }
        let users = clients_using_algs(self.storage.as_ref(), tenant.id, &removed).await?;
        if users.is_empty() {
            return Ok(());
        }
        Err(CoreError::Conflict(disabled_algs_in_use_message(
            &removed, &users,
        )))
    }

    /// Deletes a tenant and everything in it. The bootstrap tenants are `Forbidden`. Audited as
    /// `tenant_deleted` (in the system tenant).
    pub async fn delete(
        &self,
        slug: &str,
        actor: AuditActor,
        ctx: &RequestContext,
    ) -> Result<(), CoreError> {
        if is_protected_slug(slug) {
            return Err(CoreError::Forbidden);
        }
        let tenant = self.get(slug).await?;
        if !self.storage.tenants().delete(tenant.id).await? {
            return Err(CoreError::NotFound);
        }
        self.record(
            actor,
            AuditAction::TenantDeleted,
            tenant.id,
            ctx,
            AuditDetails::empty(),
        )
        .await
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

    fn tenant_with(settings: TenantSettings) -> Tenant {
        Tenant {
            id: TenantId::new_v7(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            host: None,
            settings,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    fn captcha_input(secret: &str) -> CaptchaInput {
        CaptchaInput {
            provider: CaptchaProvider::Turnstile,
            site_key: "0x-site".into(),
            secret: SecretString::from(secret.to_owned()),
        }
    }

    #[test]
    fn signing_algs_force_rs256_and_reject_unknown() {
        assert_eq!(
            normalize_signing_algs(&strings(&["ES256"])).unwrap(),
            strings(&["RS256", "ES256"])
        );
        assert_eq!(
            normalize_signing_algs(&strings(&["Ed25519", "RS256", "Ed25519", "ES256"])).unwrap(),
            strings(&["RS256", "Ed25519", "ES256"])
        );
        assert_eq!(normalize_signing_algs(&[]).unwrap(), strings(&["RS256"]));
        for bad in ["HS256", "none", "EdDSA", "es256", "PS256", ""] {
            assert!(
                matches!(
                    normalize_signing_algs(&strings(&["ES256", bad])),
                    Err(CoreError::Validation {
                        field: "signing_algs",
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn captcha_secret_is_sealed_with_the_tenant_aad() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let c = seal_captcha_secret(&kek, tenant, &captcha_input("0x-secret")).unwrap();
        assert_eq!(c.provider, CaptchaProvider::Turnstile);
        assert_eq!(c.site_key, "0x-site");
        assert!(!c.secret_sealed.contains("0x-secret"));
        let sealed = anvil_jose::encoding::b64url_decode(&c.secret_sealed).unwrap();
        let plain = kek
            .open(CAPTCHA_SECRET_PURPOSE, tenant.0.as_bytes(), &sealed)
            .unwrap();
        assert_eq!(plain.as_slice(), b"0x-secret");
        // Bound to the tenant.
        assert!(
            kek.open(
                CAPTCHA_SECRET_PURPOSE,
                TenantId::new_v7().0.as_bytes(),
                &sealed
            )
            .is_err()
        );
        for (site, secret, field) in [
            ("", "s", "captcha.site_key"),
            ("a b", "s", "captcha.site_key"),
            ("site", "", "captcha.secret"),
            ("site", "a\nb", "captcha.secret"),
        ] {
            let input = CaptchaInput {
                site_key: site.into(),
                ..captcha_input(secret)
            };
            assert!(
                matches!(
                    seal_captcha_secret(&kek, tenant, &input),
                    Err(CoreError::Validation { field: f, .. }) if f == field
                ),
                "{site:?}/{secret:?}"
            );
        }
    }

    #[test]
    fn plan_settings_set_clear_and_carry_over() {
        let kek = Kek::generate();
        let t = tenant_with(TenantSettings::default());
        assert_eq!(plan_settings(&kek, &t, None, None, false).unwrap(), None);

        // Set: sealed, other settings untouched.
        let set = CaptchaChange::Set(captcha_input("0x-secret"));
        let s = plan_settings(&kek, &t, None, Some(&set), false)
            .unwrap()
            .unwrap();
        let captcha = s.captcha.clone().expect("captcha set");
        assert_eq!(s.signing_algs, t.settings.signing_algs);

        // A settings patch keeps the current CAPTCHA and normalises algorithms.
        let with_captcha = tenant_with(s.clone());
        let requested = TenantSettings {
            signing_algs: strings(&["ES256"]),
            ..TenantSettings::default()
        };
        let s2 = plan_settings(&kek, &with_captcha, Some(requested), None, false)
            .unwrap()
            .unwrap();
        assert_eq!(s2.captcha.as_ref(), Some(&captcha));
        assert_eq!(s2.signing_algs, strings(&["RS256", "ES256"]));

        // Clear.
        let s3 = plan_settings(
            &kek,
            &with_captcha,
            None,
            Some(&CaptchaChange::Clear),
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(s3.captcha, None);

        // An injected sealed value is refused; unknown algorithms too.
        let forged = TenantSettings {
            captcha: Some(CaptchaSettings {
                secret_sealed: "AAAA".into(),
                ..captcha.clone()
            }),
            ..TenantSettings::default()
        };
        assert!(matches!(
            plan_settings(&kek, &with_captcha, Some(forged), None, false),
            Err(CoreError::Validation {
                field: "captcha",
                ..
            })
        ));
        let hs = TenantSettings {
            signing_algs: strings(&["HS256"]),
            ..TenantSettings::default()
        };
        assert!(matches!(
            plan_settings(&kek, &t, Some(hs), None, false),
            Err(CoreError::Validation {
                field: "signing_algs",
                ..
            })
        ));
    }

    #[test]
    fn admin_page_defaults_and_clamps() {
        let p = |limit| admin_page(PageRequest { after: None, limit }).limit;
        assert_eq!(p(0), 50);
        assert_eq!(p(1), 1);
        assert_eq!(p(500), 200);
    }

    #[test]
    fn default_locale_must_be_a_language_tag() {
        for ok in ["en", "de", "de-DE", "pt-BR", "zh-Hant-TW", "fil"] {
            assert!(validate_locale_tag(ok).is_ok(), "{ok}");
        }
        for bad in [
            "x y", "", "e", "english", "de_DE", "de-", "-de", "de--DE", "12", "de-DE\n",
        ] {
            assert!(
                matches!(
                    validate_locale_tag(bad),
                    Err(CoreError::Validation {
                        field: "default_locale",
                        ..
                    })
                ),
                "{bad:?}"
            );
        }
        let kek = Kek::generate();
        let t = tenant_with(TenantSettings::default());
        let bad = TenantSettings {
            default_locale: "x y".into(),
            ..TenantSettings::default()
        };
        assert!(plan_settings(&kek, &t, Some(bad), None, true).is_err());
        let ok = TenantSettings {
            default_locale: "de-DE".into(),
            ..TenantSettings::default()
        };
        let s = plan_settings(&kek, &t, Some(ok), None, false)
            .unwrap()
            .unwrap();
        assert_eq!(s.default_locale, "de-DE");
    }

    #[test]
    fn email_sign_in_needs_smtp_only_when_turned_on() {
        let kek = Kek::generate();
        let t = tenant_with(TenantSettings::default());
        for (otp, link, field) in [(true, false, "email_otp"), (false, true, "magic_link")] {
            let s = TenantSettings {
                email_otp: otp,
                magic_link: link,
                ..TenantSettings::default()
            };
            match plan_settings(&kek, &t, Some(s.clone()), None, false) {
                Err(CoreError::Validation { field: f, .. }) => assert_eq!(f, field),
                other => panic!("expected a validation error, got {other:?}"),
            }
            assert!(plan_settings(&kek, &t, Some(s.clone()), None, true).is_ok());
            // New tenants follow the same rule.
            assert!(validate_phase4_settings(None, &s, false).is_err());
            assert!(validate_phase4_settings(None, &s, true).is_ok());
            // Already on: an unrelated change without SMTP is not blocked.
            let on = tenant_with(s.clone());
            let other = TenantSettings {
                require_verified_email: true,
                ..s
            };
            assert!(plan_settings(&kek, &on, Some(other), None, false).is_ok());
        }
        // The other 0.3 settings round-trip through a plan.
        let s = TenantSettings {
            mfa_policy: crate::model::MfaPolicy::Required,
            auto_link: false,
            upstream_registration: Some(false),
            ..TenantSettings::default()
        };
        let planned = plan_settings(&kek, &t, Some(s), None, false)
            .unwrap()
            .unwrap();
        assert_eq!(planned.mfa_policy, crate::model::MfaPolicy::Required);
        assert!(!planned.auto_link);
        assert_eq!(planned.upstream_registration, Some(false));
    }
}
