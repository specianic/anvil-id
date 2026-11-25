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
//! - Logs and `last_error` contain the outbox id, template name and error kind only, never the
//!   message body, the payload or links (they carry single-use tokens).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::model::{OutboxEmail, open_payload};
use anvil_core::ports::{Clock, OutboxRepo, Storage};
use anvil_jose::Kek;

use crate::MailError;
use crate::render::EmailRenderer;
use crate::transport::{MailTransport, OutgoingMail};

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

const BASE_BACKOFF: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(3600);

/// The slice of storage the worker needs.
pub trait OutboxAccess: Send + Sync {
    fn outbox(&self) -> &dyn OutboxRepo;
}

/// Production [`OutboxAccess`]: the outbox repository of a full [`Storage`].
pub struct StorageOutbox(pub Arc<dyn Storage>);

impl OutboxAccess for StorageOutbox {
    fn outbox(&self) -> &dyn OutboxRepo {
        self.0.outbox()
    }
}

/// Delivers outbox emails.
pub struct OutboxWorker {
    pub source: Arc<dyn OutboxAccess>,
    pub transport: Arc<dyn MailTransport>,
    pub renderer: EmailRenderer,
    pub clock: Arc<dyn Clock>,
    /// Sender address (`From`) of every email.
    pub from: String,
    /// Opens the sealed outbox payloads.
    pub kek: Arc<Kek>,
}

/// Why one delivery failed. The message of each variant is what `last_error` records.
enum DeliveryError {
    Payload,
    Mail(MailError),
}

impl DeliveryError {
    fn message(&self) -> String {
        match self {
            Self::Payload => PAYLOAD_DECRYPT_ERROR.to_owned(),
            Self::Mail(e) => e.to_string(),
        }
    }
}

impl From<MailError> for DeliveryError {
    fn from(e: MailError) -> Self {
        Self::Mail(e)
    }
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
        // The open error is deliberately dropped: it is generic and the stored value is never
        // logged.
        let payload = open_payload(&self.kek, row.tenant_id, &row.payload)
            .map_err(|_| DeliveryError::Payload)?;
        let (subject, text, html) = self.renderer.render(&row.template, &payload)?;
        Ok(self
            .transport
            .send(OutgoingMail {
                to: row.to.clone(),
                from: self.from.clone(),
                subject,
                text,
                html,
            })
            .await?)
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
