//! `BrandingRepo` on Postgres: theme tokens per scope, content-addressed logos and preview
//! drafts (one per scope, looked up by the SHA-256 of the preview token).

use anvil_core::model::{
    Branding, BrandingDraft, BrandingUpdate, Logo, LogoChange, SecretHash, TenantId, ThemeTokens,
};
use anvil_core::ports::{BrandingRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::convert::{from_json, hash, map_err, to_json};

#[derive(Debug, Clone)]
pub(crate) struct PgBranding {
    pub(crate) pool: PgPool,
}

struct BrandingRow {
    tenant_id: Uuid,
    scope_key: String,
    tokens: serde_json::Value,
    custom_css: Option<String>,
    logo_sha256: Option<String>,
    logo_type: Option<String>,
    updated_at: OffsetDateTime,
}

impl BrandingRow {
    fn into_model(self) -> Result<Branding, StorageError> {
        Ok(Branding {
            tenant_id: TenantId(self.tenant_id),
            scope_key: self.scope_key,
            tokens: from_json::<ThemeTokens>("branding.tokens", self.tokens)?,
            custom_css: self.custom_css,
            logo_sha256: self.logo_sha256,
            logo_type: self.logo_type,
            updated_at: self.updated_at,
        })
    }
}

#[async_trait::async_trait]
impl BrandingRepo for PgBranding {
    async fn get(
        &self,
        tenant: TenantId,
        scope_key: &str,
    ) -> Result<Option<Branding>, StorageError> {
        sqlx::query_as!(
            BrandingRow,
            "SELECT tenant_id, scope_key, tokens, custom_css, logo_sha256, logo_type, updated_at
               FROM branding
              WHERE tenant_id = $1 AND scope_key = $2",
            tenant.0,
            scope_key,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(BrandingRow::into_model)
        .transpose()
    }

    async fn put(
        &self,
        tenant: TenantId,
        scope_key: &str,
        update: &BrandingUpdate,
        now: OffsetDateTime,
    ) -> Result<Branding, StorageError> {
        let tokens = to_json("branding.tokens", &update.tokens)?;
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        // (set logo?, sha256, type): Keep leaves the columns alone, Clear nulls them.
        let (set_logo, sha256, content_type) = match &update.logo {
            LogoChange::Keep => (false, None, None),
            LogoChange::Clear => (true, None, None),
            LogoChange::Set(logo) => {
                // Content-addressed: storing the same logo twice is a no-op.
                sqlx::query!(
                    "INSERT INTO branding_logo (tenant_id, sha256, content_type, bytes)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (tenant_id, sha256) DO NOTHING",
                    tenant.0,
                    logo.sha256,
                    logo.content_type,
                    logo.bytes,
                )
                .execute(&mut *tx)
                .await
                .map_err(map_err)?;
                (
                    true,
                    Some(logo.sha256.as_str()),
                    Some(logo.content_type.as_str()),
                )
            }
        };
        let row = sqlx::query_as!(
            BrandingRow,
            "INSERT INTO branding
                 (tenant_id, scope_key, tokens, custom_css, logo_sha256, logo_type, updated_at)
             VALUES ($1, $2, $3, $4, $6, $7, $8)
             ON CONFLICT (tenant_id, scope_key) DO UPDATE
                SET tokens = EXCLUDED.tokens,
                    custom_css = EXCLUDED.custom_css,
                    logo_sha256 = CASE WHEN $5 THEN EXCLUDED.logo_sha256
                                       ELSE branding.logo_sha256 END,
                    logo_type = CASE WHEN $5 THEN EXCLUDED.logo_type
                                     ELSE branding.logo_type END,
                    updated_at = EXCLUDED.updated_at
          RETURNING tenant_id, scope_key, tokens, custom_css, logo_sha256, logo_type,
                    updated_at",
            tenant.0,
            scope_key,
            tokens,
            update.custom_css,
            set_logo,
            sha256,
            content_type,
            now,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        row.into_model()
    }

    async fn delete(&self, tenant: TenantId, scope_key: &str) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM branding WHERE tenant_id = $1 AND scope_key = $2",
            tenant.0,
            scope_key,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn logo(&self, tenant: TenantId, sha256: &str) -> Result<Option<Logo>, StorageError> {
        let row = sqlx::query!(
            "SELECT sha256, content_type, bytes FROM branding_logo
              WHERE tenant_id = $1 AND sha256 = $2",
            tenant.0,
            sha256,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| Logo {
            content_type: r.content_type,
            sha256: r.sha256,
            bytes: r.bytes,
        }))
    }

    async fn put_draft(
        &self,
        tenant: TenantId,
        scope_key: &str,
        draft: &BrandingDraft,
        now: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let tokens = to_json("branding_draft.tokens", &draft.tokens)?;
        // One draft per scope: a new draft replaces the previous one (and its preview token).
        sqlx::query!(
            "INSERT INTO branding_draft
                 (tenant_id, scope_key, tokens, custom_css, preview_hash, preview_expires_at,
                  updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (tenant_id, scope_key) DO UPDATE
                SET tokens = EXCLUDED.tokens,
                    custom_css = EXCLUDED.custom_css,
                    preview_hash = EXCLUDED.preview_hash,
                    preview_expires_at = EXCLUDED.preview_expires_at,
                    updated_at = EXCLUDED.updated_at",
            tenant.0,
            scope_key,
            tokens,
            draft.custom_css,
            draft.preview_token_hash.as_bytes().as_slice(),
            draft.preview_expires_at,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn draft_by_preview(
        &self,
        tenant: TenantId,
        preview_token_hash: &SecretHash,
        now: OffsetDateTime,
    ) -> Result<Option<(String, BrandingDraft)>, StorageError> {
        let row = sqlx::query!(
            "SELECT scope_key, tokens, custom_css, preview_hash, preview_expires_at
               FROM branding_draft
              WHERE tenant_id = $1 AND preview_hash = $2 AND preview_expires_at > $3",
            tenant.0,
            preview_token_hash.as_bytes().as_slice(),
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        row.map(|r| {
            Ok((
                r.scope_key,
                BrandingDraft {
                    tokens: from_json("branding_draft.tokens", r.tokens)?,
                    custom_css: r.custom_css,
                    preview_token_hash: hash("branding_draft.preview_hash", &r.preview_hash)?,
                    preview_expires_at: r.preview_expires_at,
                },
            ))
        })
        .transpose()
    }
}
