//! `MailSettingsRepo` on SQLite: per-tenant email template overrides and SMTP settings.

use anvil_core::model::{EmailKind, EmailTemplate, SmtpSettings, SmtpTls, TenantId};
use anvil_core::ports::{MailSettingsRepo, StorageError};
use sqlx::SqlitePool;

use crate::convert::{map_err, ms_to_odt, odt_to_ms, parse_enum};

#[derive(Debug, Clone)]
pub(crate) struct SqliteMailSettings {
    pub(crate) writer: SqlitePool,
    pub(crate) reader: SqlitePool,
}

struct TemplateRow {
    kind: String,
    subject: String,
    body_html: String,
    body_text: String,
    updated_at: i64,
}

impl TryFrom<TemplateRow> for EmailTemplate {
    type Error = StorageError;

    fn try_from(r: TemplateRow) -> Result<Self, StorageError> {
        Ok(EmailTemplate {
            kind: parse_enum(&r.kind, EmailKind::parse, "email template kind")?,
            subject: r.subject,
            body_html: r.body_html,
            body_text: r.body_text,
            updated_at: ms_to_odt(r.updated_at)?,
        })
    }
}

#[async_trait::async_trait]
impl MailSettingsRepo for SqliteMailSettings {
    async fn template(
        &self,
        tenant: TenantId,
        kind: EmailKind,
    ) -> Result<Option<EmailTemplate>, StorageError> {
        let kind = kind.as_str();
        sqlx::query_as!(
            TemplateRow,
            r#"SELECT kind AS "kind!", subject AS "subject!", body_html AS "body_html!",
                      body_text AS "body_text!", updated_at AS "updated_at!"
                 FROM email_template WHERE tenant_id = ?1 AND kind = ?2"#,
            tenant.0,
            kind,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?
        .map(EmailTemplate::try_from)
        .transpose()
    }

    async fn list_templates(&self, tenant: TenantId) -> Result<Vec<EmailTemplate>, StorageError> {
        sqlx::query_as!(
            TemplateRow,
            r#"SELECT kind AS "kind!", subject AS "subject!", body_html AS "body_html!",
                      body_text AS "body_text!", updated_at AS "updated_at!"
                 FROM email_template WHERE tenant_id = ?1 ORDER BY kind"#,
            tenant.0,
        )
        .fetch_all(&self.reader)
        .await
        .map_err(map_err)?
        .into_iter()
        .map(EmailTemplate::try_from)
        .collect()
    }

    async fn put_template(
        &self,
        tenant: TenantId,
        template: &EmailTemplate,
    ) -> Result<(), StorageError> {
        // TRANSITIONAL(06-07): `org_invitation` is not in the email_template kind CHECK yet.
        if template.kind == EmailKind::OrgInvitation {
            return Err(StorageError::Unsupported(
                "org_invitation templates (06-07)",
            ));
        }
        let kind = template.kind.as_str();
        let updated_at = odt_to_ms(template.updated_at);
        sqlx::query!(
            "INSERT INTO email_template (tenant_id, kind, subject, body_html, body_text, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (tenant_id, kind)
             DO UPDATE SET subject = excluded.subject, body_html = excluded.body_html,
                           body_text = excluded.body_text, updated_at = excluded.updated_at",
            tenant.0,
            kind,
            template.subject,
            template.body_html,
            template.body_text,
            updated_at,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn delete_template(
        &self,
        tenant: TenantId,
        kind: EmailKind,
    ) -> Result<bool, StorageError> {
        let kind = kind.as_str();
        let done = sqlx::query!(
            "DELETE FROM email_template WHERE tenant_id = ?1 AND kind = ?2",
            tenant.0,
            kind,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }

    async fn smtp(&self, tenant: TenantId) -> Result<Option<SmtpSettings>, StorageError> {
        let row = sqlx::query!(
            r#"SELECT host AS "host!", port AS "port!", username AS "username?",
                      password_enc AS "password_enc?", from_address AS "from_address!",
                      tls AS "tls!", updated_at AS "updated_at!"
                 FROM smtp_settings WHERE tenant_id = ?1"#,
            tenant.0,
        )
        .fetch_optional(&self.reader)
        .await
        .map_err(map_err)?;
        row.map(|r| {
            Ok(SmtpSettings {
                host: r.host,
                port: u16::try_from(r.port).map_err(|_| {
                    StorageError::Corrupt(format!("smtp_settings.port {} out of range", r.port))
                })?,
                username: r.username,
                password_enc: r.password_enc,
                from: r.from_address,
                tls: parse_enum(&r.tls, SmtpTls::parse, "smtp tls")?,
                updated_at: ms_to_odt(r.updated_at)?,
            })
        })
        .transpose()
    }

    async fn put_smtp(
        &self,
        tenant: TenantId,
        settings: &SmtpSettings,
    ) -> Result<(), StorageError> {
        let port = i64::from(settings.port);
        let tls = settings.tls.as_str();
        let updated_at = odt_to_ms(settings.updated_at);
        sqlx::query!(
            "INSERT INTO smtp_settings
                 (tenant_id, host, port, username, password_enc, from_address, tls, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT (tenant_id)
             DO UPDATE SET host = excluded.host, port = excluded.port,
                           username = excluded.username, password_enc = excluded.password_enc,
                           from_address = excluded.from_address, tls = excluded.tls,
                           updated_at = excluded.updated_at",
            tenant.0,
            settings.host,
            port,
            settings.username,
            settings.password_enc,
            settings.from,
            tls,
            updated_at,
        )
        .execute(&self.writer)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn delete_smtp(&self, tenant: TenantId) -> Result<bool, StorageError> {
        let done = sqlx::query!("DELETE FROM smtp_settings WHERE tenant_id = ?1", tenant.0)
            .execute(&self.writer)
            .await
            .map_err(map_err)?;
        Ok(done.rows_affected() > 0)
    }
}
