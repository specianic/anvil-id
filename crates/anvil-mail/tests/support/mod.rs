//! Test doubles for the outbox worker tests. Test code only (CLAUDE.md): nothing here is
//! reachable from `src/`.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anvil_core::model::{
    EmailKind, EmailTemplate, NewEmail, OutboxEmail, OutboxId, SmtpSettings, TenantId, seal_payload,
};
use anvil_core::ports::{Clock, MailSettingsRepo, OutboxRepo, StorageError};
use anvil_jose::Kek;
use anvil_mail::worker::TransportFactory;
use anvil_mail::{MailError, MailTransport, OutboxAccess, OutgoingMail};
use time::OffsetDateTime;

/// A controllable clock.
pub struct TestClock(Mutex<OffsetDateTime>);

impl TestClock {
    pub fn new(start: OffsetDateTime) -> Self {
        Self(Mutex::new(start))
    }

    pub fn advance(&self, by: Duration) {
        let mut t = self.0.lock().unwrap();
        *t += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

/// Records every mail it is asked to send; fails the first `fail_times` calls.
#[derive(Default)]
pub struct CapturingTransport {
    pub sent: Mutex<Vec<OutgoingMail>>,
    pub calls: AtomicU32,
    fail_times: Mutex<u32>,
}

impl CapturingTransport {
    pub fn failing(times: u32) -> Self {
        Self {
            fail_times: Mutex::new(times),
            ..Self::default()
        }
    }

    pub fn sent(&self) -> Vec<OutgoingMail> {
        self.sent.lock().unwrap().clone()
    }

    pub fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl MailTransport for CapturingTransport {
    async fn send(&self, mail: OutgoingMail) -> Result<(), MailError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let failing = {
            let mut left = self.fail_times.lock().unwrap();
            let failing = *left > 0;
            *left = left.saturating_sub(1);
            failing
        };
        if failing {
            return Err(MailError::Send("421 service not available".into()));
        }
        self.sent.lock().unwrap().push(mail);
        Ok(())
    }
}

/// In-memory outbox with the claim/lease semantics documented on [`OutboxRepo`], plus
/// in-memory tenant mail settings.
#[derive(Default)]
pub struct MemOutbox {
    rows: Mutex<Vec<OutboxEmail>>,
    templates: Mutex<HashMap<(TenantId, EmailKind), EmailTemplate>>,
    smtp: Mutex<HashMap<TenantId, SmtpSettings>>,
}

impl MemOutbox {
    pub fn row(&self, id: OutboxId) -> OutboxEmail {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .cloned()
            .expect("row exists")
    }
}

impl OutboxAccess for MemOutbox {
    fn outbox(&self) -> &dyn OutboxRepo {
        self
    }

    fn mail_settings(&self) -> &dyn MailSettingsRepo {
        self
    }
}

#[async_trait::async_trait]
impl MailSettingsRepo for MemOutbox {
    async fn template(
        &self,
        tenant: TenantId,
        kind: EmailKind,
    ) -> Result<Option<EmailTemplate>, StorageError> {
        Ok(self.templates.lock().unwrap().get(&(tenant, kind)).cloned())
    }

    async fn list_templates(&self, tenant: TenantId) -> Result<Vec<EmailTemplate>, StorageError> {
        let mut v: Vec<_> = self
            .templates
            .lock()
            .unwrap()
            .iter()
            .filter(|((t, _), _)| *t == tenant)
            .map(|(_, tpl)| tpl.clone())
            .collect();
        v.sort_by_key(|t| t.kind.as_str());
        Ok(v)
    }

    async fn put_template(
        &self,
        tenant: TenantId,
        template: &EmailTemplate,
    ) -> Result<(), StorageError> {
        self.templates
            .lock()
            .unwrap()
            .insert((tenant, template.kind), template.clone());
        Ok(())
    }

    async fn delete_template(
        &self,
        tenant: TenantId,
        kind: EmailKind,
    ) -> Result<bool, StorageError> {
        Ok(self
            .templates
            .lock()
            .unwrap()
            .remove(&(tenant, kind))
            .is_some())
    }

    async fn smtp(&self, tenant: TenantId) -> Result<Option<SmtpSettings>, StorageError> {
        Ok(self.smtp.lock().unwrap().get(&tenant).cloned())
    }

    async fn put_smtp(
        &self,
        tenant: TenantId,
        settings: &SmtpSettings,
    ) -> Result<(), StorageError> {
        self.smtp.lock().unwrap().insert(tenant, settings.clone());
        Ok(())
    }

    async fn delete_smtp(&self, tenant: TenantId) -> Result<bool, StorageError> {
        Ok(self.smtp.lock().unwrap().remove(&tenant).is_some())
    }
}

/// A [`TransportFactory`] that hands out one [`CapturingTransport`] per tenant and records
/// every settings value it was asked for.
#[derive(Default)]
pub struct RecordingFactory {
    pub requests: Mutex<Vec<(TenantId, SmtpSettings)>>,
    pub evicted: Mutex<Vec<TenantId>>,
    transports: Mutex<HashMap<TenantId, Arc<CapturingTransport>>>,
}

impl RecordingFactory {
    /// The transport handed out for `tenant` (created on first use).
    pub fn for_tenant(&self, tenant: TenantId) -> Arc<CapturingTransport> {
        Arc::clone(self.transports.lock().unwrap().entry(tenant).or_default())
    }

    pub fn requests(&self) -> Vec<(TenantId, SmtpSettings)> {
        self.requests.lock().unwrap().clone()
    }
}

impl TransportFactory for RecordingFactory {
    fn transport(
        &self,
        tenant: TenantId,
        settings: &SmtpSettings,
    ) -> Result<Arc<dyn MailTransport>, MailError> {
        self.requests
            .lock()
            .unwrap()
            .push((tenant, settings.clone()));
        Ok(self.for_tenant(tenant))
    }

    fn evict(&self, tenant: TenantId) {
        self.evicted.lock().unwrap().push(tenant);
    }
}

#[async_trait::async_trait]
impl OutboxRepo for MemOutbox {
    async fn enqueue(&self, tenant: TenantId, email: &NewEmail) -> Result<(), StorageError> {
        let mut rows = self.rows.lock().unwrap();
        if rows.iter().any(|r| r.id == email.id) {
            return Err(StorageError::Conflict("outbox id".into()));
        }
        rows.push(OutboxEmail {
            id: email.id,
            tenant_id: tenant,
            to: email.to.clone(),
            template: email.template.clone(),
            payload: email.payload.clone(),
            attempts: 0,
            next_attempt_at: email.created_at,
            created_at: email.created_at,
            expires_at: email.expires_at,
            sent_at: None,
            last_error: None,
        });
        Ok(())
    }

    async fn claim_due(
        &self,
        now: OffsetDateTime,
        limit: u32,
        lease: Duration,
    ) -> Result<Vec<OutboxEmail>, StorageError> {
        let mut rows = self.rows.lock().unwrap();
        let mut due: Vec<&mut OutboxEmail> = rows
            .iter_mut()
            .filter(|r| r.sent_at.is_none() && r.next_attempt_at <= now && r.expires_at > now)
            .collect();
        due.sort_by_key(|r| (r.created_at, r.id));
        Ok(due
            .into_iter()
            .take(limit as usize)
            .map(|r| {
                r.next_attempt_at = now + lease;
                r.attempts += 1;
                r.clone()
            })
            .collect())
    }

    async fn mark_sent(&self, id: OutboxId, now: OffsetDateTime) -> Result<bool, StorageError> {
        let mut rows = self.rows.lock().unwrap();
        Ok(match rows.iter_mut().find(|r| r.id == id) {
            Some(r) => {
                r.sent_at = Some(now);
                true
            }
            None => false,
        })
    }

    async fn mark_failed(
        &self,
        id: OutboxId,
        error: &str,
        next_attempt_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let mut rows = self.rows.lock().unwrap();
        Ok(match rows.iter_mut().find(|r| r.id == id) {
            Some(r) => {
                r.last_error = Some(error.to_owned());
                r.next_attempt_at = next_attempt_at;
                true
            }
            None => false,
        })
    }
}

pub fn start_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

pub fn payload(email: &str, link: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("tenant_name".to_owned(), "Acme".to_owned()),
        ("email".to_owned(), email.to_owned()),
        ("link".to_owned(), link.to_owned()),
        ("expires_in".to_owned(), "1 hour".to_owned()),
    ])
}

/// A new email for `tenant` created at `created_at`, valid for one day, with the standard
/// payload sealed under `kek` (as the core services store it).
pub fn new_email(
    kek: &Kek,
    tenant: TenantId,
    to: &str,
    template: &str,
    link: &str,
    created_at: OffsetDateTime,
) -> NewEmail {
    email_with_payload(kek, tenant, to, template, &payload(to, link), created_at)
}

/// Like [`new_email`] with an explicit (plaintext) payload, sealed under `kek`.
pub fn email_with_payload(
    kek: &Kek,
    tenant: TenantId,
    to: &str,
    template: &str,
    payload: &BTreeMap<String, String>,
    created_at: OffsetDateTime,
) -> NewEmail {
    NewEmail {
        id: OutboxId::new_v7(),
        to: to.to_owned(),
        template: template.to_owned(),
        payload: seal_payload(kek, tenant, payload).expect("seal test payload"),
        created_at,
        expires_at: created_at + Duration::from_secs(86_400),
    }
}
