//! TRANSITIONAL(03-06): Phase 3 storage methods not implemented on this backend yet.
//!
//! Every method here (and every Phase 3 method in the existing repositories, which delegate to
//! [`unsupported`]) returns [`StorageError::Unsupported`]: an explicit error, never a success.
//! Plan 03-06 adds the 0003 migration and replaces this module.

use anvil_core::model::{
    AuditEvent, AuditQuery, EmailKind, EmailTemplate, NewAuditEvent, Page, SmtpSettings, TenantId,
};
use anvil_core::ports::{AuditRepo, JobRepo, MailSettingsRepo, StorageError};
use time::OffsetDateTime;

/// The explicit "not implemented yet" result of a Phase 3 storage method.
pub(crate) fn unsupported<T>(op: &'static str) -> Result<T, StorageError> {
    Err(StorageError::Unsupported(op))
}

/// Audit, mail-settings and job-lease repositories (TRANSITIONAL(03-06)).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Pending;

#[async_trait::async_trait]
impl AuditRepo for Pending {
    async fn append(&self, _tenant: TenantId, _event: &NewAuditEvent) -> Result<(), StorageError> {
        crate::pending::unsupported("AuditRepo::append")
    }

    async fn query(
        &self,
        _tenant: TenantId,
        _query: &AuditQuery,
    ) -> Result<Page<AuditEvent>, StorageError> {
        crate::pending::unsupported("AuditRepo::query")
    }

    async fn purge_before(&self, _cutoff: OffsetDateTime) -> Result<u64, StorageError> {
        crate::pending::unsupported("AuditRepo::purge_before")
    }
}

#[async_trait::async_trait]
impl MailSettingsRepo for Pending {
    async fn template(
        &self,
        _tenant: TenantId,
        _kind: EmailKind,
    ) -> Result<Option<EmailTemplate>, StorageError> {
        crate::pending::unsupported("MailSettingsRepo::template")
    }

    async fn list_templates(&self, _tenant: TenantId) -> Result<Vec<EmailTemplate>, StorageError> {
        crate::pending::unsupported("MailSettingsRepo::list_templates")
    }

    async fn put_template(
        &self,
        _tenant: TenantId,
        _template: &EmailTemplate,
    ) -> Result<(), StorageError> {
        crate::pending::unsupported("MailSettingsRepo::put_template")
    }

    async fn delete_template(
        &self,
        _tenant: TenantId,
        _kind: EmailKind,
    ) -> Result<bool, StorageError> {
        crate::pending::unsupported("MailSettingsRepo::delete_template")
    }

    async fn smtp(&self, _tenant: TenantId) -> Result<Option<SmtpSettings>, StorageError> {
        crate::pending::unsupported("MailSettingsRepo::smtp")
    }

    async fn put_smtp(
        &self,
        _tenant: TenantId,
        _settings: &SmtpSettings,
    ) -> Result<(), StorageError> {
        crate::pending::unsupported("MailSettingsRepo::put_smtp")
    }

    async fn delete_smtp(&self, _tenant: TenantId) -> Result<bool, StorageError> {
        crate::pending::unsupported("MailSettingsRepo::delete_smtp")
    }
}

#[async_trait::async_trait]
impl JobRepo for Pending {
    async fn try_lease(
        &self,
        _name: &str,
        _owner: &str,
        _until: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        crate::pending::unsupported("JobRepo::try_lease")
    }

    async fn release(&self, _name: &str, _owner: &str) -> Result<bool, StorageError> {
        crate::pending::unsupported("JobRepo::release")
    }
}
