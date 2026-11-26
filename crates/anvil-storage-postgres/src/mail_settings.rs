//! `MailSettingsRepo` on Postgres: per-tenant email template overrides and SMTP settings.

use anvil_core::model::{EmailKind, EmailTemplate, SmtpSettings, SmtpTls, TenantId};
use anvil_core::ports::{MailSettingsRepo, StorageError};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::convert::{enum_from, map_err};

#[derive(Debug, Clone)]
pub(crate) struct PgMailSettings {
    pub(crate) pool: PgPool,
}

struct TemplateRow {
    kind: String,
    subject: String,
    body_html: String,
    body_text: String,
    updated_at: OffsetDateTime,
}

impl TemplateRow {
    fn into_model(self) -> Result<EmailTemplate, StorageError> {
        Ok(EmailTemplate {
            kind: enum_from("email_template.kind", &self.kind, EmailKind::parse)?,
            subject: self.subject,
            body_html: self.body_html,
            body_text: self.body_text,
            updated_at: self.updated_at,
        })
    }
}

#[async_trait::async_trait]
impl MailSettingsRepo for PgMailSettings {
    async fn template(
        &self,
        tenant: TenantId,
        kind: EmailKind,
    ) -> Result<Option<EmailTemplate>, StorageError> {
        sqlx::query_as!(
            TemplateRow,
            "SELECT kind, subject, body_html, body_text, updated_at
               FROM email_template
              WHERE tenant_id = $1 AND kind = $2",
            tenant.0,
            kind.as_str(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        .map(TemplateRow::into_model)
        .transpose()
    }

    async fn list_templates(&self, tenant: TenantId) -> Result<Vec<EmailTemplate>, StorageError> {
        sqlx::query_as!(
            TemplateRow,
            "SELECT kind, subject, body_html, body_text, updated_at
               FROM email_template
              WHERE tenant_id = $1
              ORDER BY kind COLLATE \"C\"",
            tenant.0,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(TemplateRow::into_model)
        .collect()
    }

    async fn put_template(&self, tenant: TenantId, t: &EmailTemplate) -> Result<(), StorageError> {
        sqlx::query!(
            "INSERT INTO email_template
                 (tenant_id, kind, subject, body_html, body_text, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, kind) DO UPDATE
                SET subject = EXCLUDED.subject,
                    body_html = EXCLUDED.body_html,
                    body_text = EXCLUDED.body_text,
                    updated_at = EXCLUDED.updated_at",
            tenant.0,
            t.kind.as_str(),
            t.subject,
            t.body_html,
            t.body_text,
            t.updated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn delete_template(
        &self,
        tenant: TenantId,
        kind: EmailKind,
    ) -> Result<bool, StorageError> {
        let done = sqlx::query!(
            "DELETE FROM email_template WHERE tenant_id = $1 AND kind = $2",
            tenant.0,
            kind.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn smtp(&self, tenant: TenantId) -> Result<Option<SmtpSettings>, StorageError> {
        let Some(r) = sqlx::query!(
            "SELECT host, port, username, password_enc, from_address, tls, updated_at
               FROM smtp_settings
              WHERE tenant_id = $1",
            tenant.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?
        else {
            return Ok(None);
        };
        Ok(Some(SmtpSettings {
            host: r.host,
            port: u16::try_from(r.port).map_err(|_| {
                StorageError::Corrupt(format!("smtp_settings.port: out of range {}", r.port))
            })?,
            username: r.username,
            password_enc: r.password_enc,
            from: r.from_address,
            tls: enum_from("smtp_settings.tls", &r.tls, SmtpTls::parse)?,
            updated_at: r.updated_at,
        }))
    }

    async fn put_smtp(&self, tenant: TenantId, s: &SmtpSettings) -> Result<(), StorageError> {
        sqlx::query!(
            "INSERT INTO smtp_settings
                 (tenant_id, host, port, username, password_enc, from_address, tls, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (tenant_id) DO UPDATE
                SET host = EXCLUDED.host,
                    port = EXCLUDED.port,
                    username = EXCLUDED.username,
                    password_enc = EXCLUDED.password_enc,
                    from_address = EXCLUDED.from_address,
                    tls = EXCLUDED.tls,
                    updated_at = EXCLUDED.updated_at",
            tenant.0,
            s.host,
            i32::from(s.port),
            s.username,
            s.password_enc,
            s.from,
            s.tls.as_str(),
            s.updated_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn delete_smtp(&self, tenant: TenantId) -> Result<bool, StorageError> {
        let done = sqlx::query!("DELETE FROM smtp_settings WHERE tenant_id = $1", tenant.0)
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}
