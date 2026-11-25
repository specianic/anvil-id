//! `BrandingRepo` on SQLite.
//!
//! One `branding` row per (tenant, scope) holds the published record (`tokens`, `custom_css`,
//! `logo_*`) and the scope's preview draft (`draft_*`, `preview_hash`, `preview_expires_at`).
//! A scope that only has a draft has `tokens IS NULL` and is invisible to `get`. Logo bytes live
//! in `branding_logo`, deduplicated by sha256 per tenant.

use anvil_core::model::{
    Branding, BrandingDraft, BrandingUpdate, Logo, LogoChange, SecretHash, TenantId, ThemeTokens,
};
use anvil_core::ports::{BrandingRepo, StorageError};
use sqlx::SqlitePool;
use time::OffsetDateTime;

use crate::convert::{blob_to_hash, from_json, map_err, ms_to_odt, odt_to_ms, to_json};

#[derive(Debug, Clone)]
pub(crate) struct SqliteBranding {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

struct BrandingRow {
    tenant_id: uuid::Uuid,
    scope_key: String,
    tokens: String,
    custom_css: Option<String>,
    logo_sha256: Option<String>,
    logo_type: Option<String>,
    updated_at: i64,
}

impl TryFrom<BrandingRow> for Branding {
    type Error = StorageError;

    fn try_from(r: BrandingRow) -> Result<Self, StorageError> {
        Ok(Branding {
            tenant_id: TenantId(r.tenant_id),
            scope_key: r.scope_key,
            tokens: from_json::<ThemeTokens>(&r.tokens, "branding.tokens")?,
            custom_css: r.custom_css,
            logo_sha256: r.logo_sha256,
            logo_type: r.logo_type,
            updated_at: ms_to_odt(r.updated_at)?,
        })
    }
}

#[async_trait::async_trait]
impl BrandingRepo for SqliteBranding {
    async fn get(
        &self,
        tenant: TenantId,
        scope_key: &str,
    ) -> Result<Option<Branding>, StorageError> {
        sqlx::query_as!(
            BrandingRow,
            r#"SELECT tenant_id AS "tenant_id!: uuid::Uuid", scope_key AS "scope_key!",
                      tokens AS "tokens!", custom_css AS "custom_css?",
                      logo_sha256 AS "logo_sha256?", logo_type AS "logo_type?",
                      updated_at AS "updated_at!"
                 FROM branding
                WHERE tenant_id = ?1 AND scope_key = ?2 AND tokens IS NOT NULL"#,
            tenant.0,
            scope_key,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(Branding::try_from)
        .transpose()
    }

    async fn put(
        &self,
        tenant: TenantId,
        scope_key: &str,
        update: &BrandingUpdate,
        now: OffsetDateTime,
    ) -> Result<Branding, StorageError> {
        let tokens = to_json(&update.tokens, "branding.tokens")?;
        let now_ms = odt_to_ms(now);
        let keep_logo = matches!(update.logo, LogoChange::Keep);
        let (logo_sha256, logo_type) = match &update.logo {
            LogoChange::Set(logo) => (Some(logo.sha256.as_str()), Some(logo.content_type.as_str())),
            LogoChange::Keep | LogoChange::Clear => (None, None),
        };
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        if let LogoChange::Set(logo) = &update.logo {
            // Content-addressed: an existing row with this hash already holds these bytes.
            sqlx::query!(
                "INSERT OR IGNORE INTO branding_logo (tenant_id, sha256, content_type, bytes)
                 VALUES (?1, ?2, ?3, ?4)",
                tenant.0,
                logo.sha256,
                logo.content_type,
                logo.bytes,
            )
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        }
        let row = sqlx::query_as!(
            BrandingRow,
            r#"INSERT INTO branding
                   (tenant_id, scope_key, tokens, custom_css, logo_sha256, logo_type, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
               ON CONFLICT (tenant_id, scope_key) DO UPDATE
                  SET tokens = excluded.tokens,
                      custom_css = excluded.custom_css,
                      logo_sha256 = CASE WHEN ?8 THEN branding.logo_sha256
                                         ELSE excluded.logo_sha256 END,
                      logo_type = CASE WHEN ?8 THEN branding.logo_type
                                       ELSE excluded.logo_type END,
                      updated_at = excluded.updated_at
            RETURNING tenant_id AS "tenant_id!: uuid::Uuid", scope_key AS "scope_key!",
                      tokens AS "tokens!", custom_css AS "custom_css?",
                      logo_sha256 AS "logo_sha256?", logo_type AS "logo_type?",
                      updated_at AS "updated_at!""#,
            tenant.0,
            scope_key,
            tokens,
            update.custom_css,
            logo_sha256,
            logo_type,
            now_ms,
            keep_logo,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_err)?;
        let stored = Branding::try_from(row)?;
        tx.commit().await.map_err(map_err)?;
        Ok(stored)
    }

    async fn delete(&self, tenant: TenantId, scope_key: &str) -> Result<bool, StorageError> {
        let mut tx = self.writer.begin().await.map_err(map_err)?;
        // Unpublish; the scope's preview draft (if any) stays until it is replaced or expires.
        let done = sqlx::query!(
            "UPDATE branding
                SET tokens = NULL, custom_css = NULL, logo_sha256 = NULL, logo_type = NULL
              WHERE tenant_id = ?1 AND scope_key = ?2 AND tokens IS NOT NULL",
            tenant.0,
            scope_key,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        sqlx::query!(
            "DELETE FROM branding
              WHERE tenant_id = ?1 AND scope_key = ?2 AND tokens IS NULL
                AND draft_tokens IS NULL",
            tenant.0,
            scope_key,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn logo(&self, tenant: TenantId, sha256: &str) -> Result<Option<Logo>, StorageError> {
        let row = sqlx::query!(
            r#"SELECT sha256 AS "sha256!", content_type AS "content_type!", bytes AS "bytes!"
                 FROM branding_logo WHERE tenant_id = ?1 AND sha256 = ?2"#,
            tenant.0,
            sha256,
        )
        .fetch_optional(&self.reader)
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
        let tokens = to_json(&draft.tokens, "branding.draft_tokens")?;
        let hash = draft.preview_token_hash.as_bytes().as_slice();
        let expires_ms = odt_to_ms(draft.preview_expires_at);
        let now_ms = odt_to_ms(now);
        // `updated_at` belongs to the published record: set only when the row is new.
        sqlx::query!(
            "INSERT INTO branding
                 (tenant_id, scope_key, draft_tokens, draft_css, preview_hash, preview_expires_at,
                  updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (tenant_id, scope_key) DO UPDATE
                SET draft_tokens = excluded.draft_tokens,
                    draft_css = excluded.draft_css,
                    preview_hash = excluded.preview_hash,
                    preview_expires_at = excluded.preview_expires_at",
            tenant.0,
            scope_key,
            tokens,
            draft.custom_css,
            hash,
            expires_ms,
            now_ms,
        )
        .execute(&self.writer)
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
        let hash = preview_token_hash.as_bytes().as_slice();
        let now_ms = odt_to_ms(now);
        let row = sqlx::query!(
            r#"SELECT scope_key AS "scope_key!", draft_tokens AS "draft_tokens!",
                      draft_css AS "draft_css?", preview_hash AS "preview_hash!",
                      preview_expires_at AS "preview_expires_at!"
                 FROM branding
                WHERE tenant_id = ?1 AND preview_hash = ?2 AND preview_expires_at > ?3"#,
            tenant.0,
            hash,
            now_ms,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?;
        row.map(|r| {
            Ok((
                r.scope_key,
                BrandingDraft {
                    tokens: from_json(&r.draft_tokens, "branding.draft_tokens")?,
                    custom_css: r.draft_css,
                    preview_token_hash: blob_to_hash(&r.preview_hash, "branding.preview_hash")?,
                    preview_expires_at: ms_to_odt(r.preview_expires_at)?,
                },
            ))
        })
        .transpose()
    }
}
