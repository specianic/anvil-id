//! The outbox worker: claims due outbox rows, renders and sends them, and records the outcome
//! (RESEARCH Pattern 8).
//!
//! - Claims use a 2-minute lease, so a crashed worker's rows are retried after the lease.
//! - Attempt `n` failing reschedules at `now + min(30 s * 2^(n-1), 1 h)`.
//! - After [`MAX_ATTEMPTS`] attempts the row is parked at its `expires_at`, so it is never
//!   claimed again (claims require `expires_at > now`).
//! - Payloads are stored sealed with the KEK (`anvil_core::model::seal_payload`). The worker
//!   opens each payload immediately before rendering. A payload that cannot be opened (wrong KEK,
//!   tampered or unsealed row) is never sent: the attempt is recorded as failed with the generic
//!   error [`PAYLOAD_DECRYPT_ERROR`].
//! - A payload without an `email` variable gets the row's recipient as `email` (notices sealed
//!   before the address is known, such as the `password_changed` notice of a recovery). A
//!   payload-provided `email` is never replaced.
//! - Logs and `last_error` contain the outbox id, template name and error kind only, never the
//!   message body, the payload or links (they carry single-use tokens).
//!
//! # Per-tenant templates and transports
//!
//! - The tenant's template override for the row's kind (`MailSettingsRepo::template`) is
//!   rendered when present, the theme default otherwise.
//! - The tenant's SMTP settings (`MailSettingsRepo::smtp`) are used when present, through a
//!   transport built by the [`TransportFactory`] (production: [`SmtpTransportFactory`], which
//!   opens the sealed password and caches one transport per tenant keyed by `updated_at`); the
//!   sender is the tenant's `from`. Otherwise the installation transport is used. With neither,
//!   the attempt fails with [`NO_SMTP_ERROR`] and the normal backoff.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anvil_core::model::{EmailKind, OutboxEmail, SmtpSettings, TenantId, open_payload};
use anvil_core::ports::{Clock, MailSettingsRepo, OutboxRepo, Storage, StorageError};
use anvil_core::service::mail_settings::smtp_connection;
use anvil_jose::Kek;
use time::OffsetDateTime;

use crate::MailError;
use crate::render::EmailRenderer;
use crate::transport::{MailTransport, OutgoingMail, SmtpTransport};

/// Claim lease: a claimed row is invisible to other claimers for this long.
pub const CLAIM_LEASE: Duration = Duration::from_secs(120);
/// Rows claimed per batch.
pub const BATCH_SIZE: u32 = 50;
/// Attempts after which a row is given up.
pub const MAX_ATTEMPTS: u32 = 8;
/// Delay between polls when the outbox is idle (or after an error).
pub const IDLE_POLL: Duration = Duration::from_secs(2);
/// `last_error` of a row whose sealed payload cannot be opened.
pub const PAYLOAD_DECRYPT_ERROR: &str = "payload could not be decrypted";
/// `last_error` of a row whose tenant has no SMTP settings when there is no installation SMTP.
pub const NO_SMTP_ERROR: &str = "no SMTP configured";

const BASE_BACKOFF: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(3600);

/// The slice of storage the worker needs.
pub trait OutboxAccess: Send + Sync {
    fn outbox(&self) -> &dyn OutboxRepo;
    /// Tenant template overrides and SMTP settings.
    fn mail_settings(&self) -> &dyn MailSettingsRepo;
}

/// Production [`OutboxAccess`]: the outbox and mail-settings repositories of a full
/// [`Storage`].
pub struct StorageOutbox(pub Arc<dyn Storage>);

impl OutboxAccess for StorageOutbox {
    fn outbox(&self) -> &dyn OutboxRepo {
        self.0.outbox()
    }

    fn mail_settings(&self) -> &dyn MailSettingsRepo {
        self.0.mail_settings()
    }
}

/// Builds the transport for a tenant's SMTP settings.
pub trait TransportFactory: Send + Sync {
    /// The transport for `settings` of `tenant`. Errors never contain the password.
    fn transport(
        &self,
        tenant: TenantId,
        settings: &SmtpSettings,
    ) -> Result<Arc<dyn MailTransport>, MailError>;

    /// Drops any cached transport of `tenant` (its settings were removed).
    fn evict(&self, tenant: TenantId);
}

/// A cached tenant transport and the `updated_at` of the settings it was built from.
type CachedTransport = (OffsetDateTime, Arc<dyn MailTransport>);

/// Production [`TransportFactory`]: an [`SmtpTransport`] per tenant, built from the settings
/// with the password opened by the KEK, cached until the settings' `updated_at` changes.
pub struct SmtpTransportFactory {
    kek: Arc<Kek>,
    cache: Mutex<HashMap<TenantId, CachedTransport>>,
}

impl SmtpTransportFactory {
    pub fn new(kek: Arc<Kek>) -> Self {
        Self {
            kek,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

impl std::fmt::Debug for SmtpTransportFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpTransportFactory")
            .finish_non_exhaustive()
    }
}

impl TransportFactory for SmtpTransportFactory {
    fn transport(
        &self,
        tenant: TenantId,
        settings: &SmtpSettings,
    ) -> Result<Arc<dyn MailTransport>, MailError> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| MailError::Config("transport cache poisoned".into()))?;
        if let Some((updated_at, transport)) = cache.get(&tenant)
            && *updated_at == settings.updated_at
        {
            return Ok(Arc::clone(transport));
        }
        // The open error is generic; the sealed and opened values are never logged.
        let conn = smtp_connection(&self.kek, tenant, settings)
            .map_err(|_| MailError::Config("SMTP password could not be decrypted".into()))?;
        let transport: Arc<dyn MailTransport> = Arc::new(SmtpTransport::from_settings(&conn)?);
        cache.insert(tenant, (settings.updated_at, Arc::clone(&transport)));
        Ok(transport)
    }

    fn evict(&self, tenant: TenantId) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.remove(&tenant);
        }
    }
}

/// Delivers outbox emails.
pub struct OutboxWorker {
    pub source: Arc<dyn OutboxAccess>,
    /// The installation transport (`smtp_url`), used for tenants without SMTP settings.
    pub transport: Option<Arc<dyn MailTransport>>,
    /// Builds transports from tenant SMTP settings.
    pub transports: Arc<dyn TransportFactory>,
    pub renderer: EmailRenderer,
    pub clock: Arc<dyn Clock>,
    /// Sender address (`From`) of emails sent through the installation transport.
    pub from: String,
    /// Opens the sealed outbox payloads.
    pub kek: Arc<Kek>,
}

/// Why one delivery failed. The message of each variant is what `last_error` records.
enum DeliveryError {
    Payload,
    NoSmtp,
    Mail(MailError),
}

impl DeliveryError {
    fn message(&self) -> String {
        match self {
            Self::Payload => PAYLOAD_DECRYPT_ERROR.to_owned(),
            Self::NoSmtp => NO_SMTP_ERROR.to_owned(),
            Self::Mail(e) => e.to_string(),
        }
    }
}

impl From<StorageError> for DeliveryError {
    fn from(e: StorageError) -> Self {
        Self::Mail(MailError::Storage(e))
    }
}

impl From<MailError> for DeliveryError {
    fn from(e: MailError) -> Self {
        Self::Mail(e)
    }
}

/// Inserts `to` as the `email` template variable when (and only when) the payload has none.
fn fill_recipient(payload: &mut BTreeMap<String, String>, to: &str) {
    payload
        .entry("email".to_owned())
        .or_insert_with(|| to.to_owned());
}

/// Backoff after failed attempt `attempt` (1-based): `min(30 s * 2^(attempt-1), 1 h)`.
pub fn backoff(attempt: u32) -> Duration {
    let exp = attempt.saturating_sub(1).min(16);
    BASE_BACKOFF.saturating_mul(1u32 << exp).min(MAX_BACKOFF)
}

impl OutboxWorker {
    /// Processes one batch of due emails. Returns how many were sent.
    ///
    /// A failure of one email (render or send) is recorded on that row and does not stop the
    /// batch. Only a failure to claim is returned as an error.
    pub async fn run_once(&self) -> Result<usize, MailError> {
        self.batch().await.map(|(_, sent)| sent)
    }

    /// Runs until `shutdown` completes, polling every [`IDLE_POLL`] when idle. A full batch is
    /// followed immediately by the next one. A batch in progress is finished before shutdown.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            let full = match self.batch().await {
                Ok((claimed, _)) => claimed >= BATCH_SIZE as usize,
                Err(e) => {
                    tracing::warn!(error = %e, "outbox batch failed");
                    false
                }
            };
            if full {
                continue;
            }
            tokio::select! {
                () = &mut shutdown => break,
                () = tokio::time::sleep(IDLE_POLL) => {}
            }
        }
    }

    /// Returns `(claimed, sent)`.
    async fn batch(&self) -> Result<(usize, usize), MailError> {
        let repo = self.source.outbox();
        let rows = repo
            .claim_due(self.clock.now(), BATCH_SIZE, CLAIM_LEASE)
            .await?;
        let claimed = rows.len();
        let mut sent = 0;
        for row in rows {
            match self.deliver(&row).await {
                Ok(()) => {
                    sent += 1;
                    if let Err(e) = repo.mark_sent(row.id, self.clock.now()).await {
                        tracing::error!(outbox_id = %row.id.0, error = %e, "could not mark email sent");
                    }
                }
                Err(err) => self.record_failure(repo, &row, &err).await,
            }
        }
        Ok((claimed, sent))
    }

    async fn deliver(&self, row: &OutboxEmail) -> Result<(), DeliveryError> {
        let (transport, from) = self.resolve_transport(row.tenant_id).await?;
        // The open error is deliberately dropped: it is generic and the stored value is never
        // logged.
        let mut payload = open_payload(&self.kek, row.tenant_id, &row.payload)
            .map_err(|_| DeliveryError::Payload)?;
        fill_recipient(&mut payload, &row.to);
        let (subject, text, html) = match EmailKind::parse(&row.template) {
            Some(kind) => {
                let override_ = self
                    .source
                    .mail_settings()
                    .template(row.tenant_id, kind)
                    .await?;
                self.renderer
                    .render_with(override_.as_ref(), kind, &payload)?
            }
            None => self.renderer.render(&row.template, &payload)?,
        };
        Ok(transport
            .send(OutgoingMail {
                to: row.to.clone(),
                from,
                subject,
                text,
                html,
            })
            .await?)
    }

    /// The tenant's transport and sender, else the installation's, else [`NO_SMTP_ERROR`].
    async fn resolve_transport(
        &self,
        tenant: TenantId,
    ) -> Result<(Arc<dyn MailTransport>, String), DeliveryError> {
        match self.source.mail_settings().smtp(tenant).await? {
            Some(settings) => {
                let transport = self.transports.transport(tenant, &settings)?;
                Ok((transport, settings.from))
            }
            None => {
                self.transports.evict(tenant);
                match &self.transport {
                    Some(t) => Ok((Arc::clone(t), self.from.clone())),
                    None => Err(DeliveryError::NoSmtp),
                }
            }
        }
    }

    async fn record_failure(&self, repo: &dyn OutboxRepo, row: &OutboxEmail, err: &DeliveryError) {
        // `attempts` already counts this attempt (claiming increments it).
        let attempt = row.attempts.max(1);
        let now = self.clock.now();
        let next = if attempt >= MAX_ATTEMPTS {
            row.expires_at
        } else {
            (now + backoff(attempt)).min(row.expires_at)
        };
        let message = err.message();
        tracing::warn!(
            outbox_id = %row.id.0,
            template = %row.template,
            attempt,
            gave_up = attempt >= MAX_ATTEMPTS,
            error = %message,
            "email delivery failed"
        );
        if let Err(e) = repo.mark_failed(row.id, &message, next).await {
            tracing::error!(outbox_id = %row.id.0, error = %e, "could not record email failure");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_fills_a_missing_email_only() {
        let mut absent = BTreeMap::from([("tenant_name".to_owned(), "Acme".to_owned())]);
        fill_recipient(&mut absent, "alice@example.test");
        assert_eq!(absent["email"], "alice@example.test");
        assert_eq!(absent["tenant_name"], "Acme");

        let mut present = BTreeMap::from([("email".to_owned(), "bob@example.test".to_owned())]);
        fill_recipient(&mut present, "alice@example.test");
        assert_eq!(present["email"], "bob@example.test");
        assert_eq!(present.len(), 1);
    }

    #[test]
    fn backoff_doubles_from_30s_and_caps_at_1h() {
        assert_eq!(backoff(1), Duration::from_secs(30));
        assert_eq!(backoff(2), Duration::from_secs(60));
        assert_eq!(backoff(3), Duration::from_secs(120));
        assert_eq!(backoff(7), Duration::from_secs(1920));
        assert_eq!(backoff(8), Duration::from_secs(3600));
        assert_eq!(backoff(u32::MAX), Duration::from_secs(3600));
        assert_eq!(backoff(0), Duration::from_secs(30));
    }
}
