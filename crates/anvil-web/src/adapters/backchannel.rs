//! Back-channel logout delivery (OIDC Back-Channel Logout 1.0, OIDC-12): logout tokens POSTed to
//! each RP's `backchannel_logout_uri` by a leased background job with retries, through the single
//! SSRF-guarded [`crate::adapters::outbound::OutboundClient`], woken by
//! [`crate::state::AppState::logout_wake`].
//!
//! - Revoking a session enqueues one delivery row per RP the session signed in to (storage, same
//!   transaction). The worker claims due rows installation-wide with a lease
//!   (`LogoutRepo::claim_due_deliveries`), so concurrent nodes never deliver the same row twice
//!   and a crashed node's rows come back after the lease.
//! - Each row gets a freshly signed logout token at send time
//!   ([`LogoutService::prepare_delivery`]): `typ: logout+jwt`, the client's ID-token algorithm,
//!   claims `iss`/`aud`/`iat`/`exp` (2 minutes)/`jti`/`sub`/`sid`/`events`, no `nonce`.
//! - The request is `POST` with only `logout_token` in an `application/x-www-form-urlencoded`
//!   body. The response body is read (capped at 64 KiB) and discarded.
//! - [`classify_delivery`] decides: 200/204 delivered; other statuses and blocked destinations
//!   give up; 5xx, network errors and timeouts retry with `10 s * 2^n` backoff (cap 1 h) until
//!   24 h after enqueue. A retry that would fall at or after that deadline is a give-up now
//!   (reason `expired`), because such a row is never claimed again and would otherwise vanish
//!   unaudited. A client that was deleted or lost its URI gives up.
//! - Give-ups are audited as `backchannel_logout_failed` in the row's tenant (system actor, the
//!   delivery id as target, details client id, attempts and a fixed reason). Logs and audit
//!   never contain the token or the URI.
//! - Rows of one batch are delivered concurrently, so a batch takes about one request timeout
//!   (10 s), well inside the 2-minute lease.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::error::CoreError;
use anvil_core::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, DeliveryResult, LOGOUT_DELIVERY_TTL,
    LogoutDelivery, PublicUrl, RequestContext,
};
use anvil_core::oauth::logout::{DeliveryOutcome, classify_delivery, next_attempt};
use anvil_core::ports::{Clock, Storage};
use anvil_core::service::audit::AuditService;
use anvil_core::service::key::KeyService;
use anvil_core::service::logout::LogoutService;
use anvil_jose::Kek;
use secrecy::ExposeSecret as _;
use tokio::sync::Notify;
use tokio::task::JoinSet;

use crate::adapters::outbound::{LIMIT_TOKEN, OutboundClient, OutboundError, read_capped};

/// Rows claimed per batch.
pub const BATCH_SIZE: u32 = 20;
/// Delay between polls when no logout wakes the worker.
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);
/// Claim lease: a claimed row is invisible to other claimers for this long.
pub const CLAIM_LEASE: Duration = Duration::from_secs(120);
/// `last_error` of a row whose token could not be prepared for a server-side reason.
const INTERNAL_ERROR: &str = "internal error";

/// What one [`LogoutDeliveryWorker::run_once`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunReport {
    pub claimed: usize,
    pub delivered: usize,
    pub retried: usize,
    pub given_up: usize,
}

struct Inner {
    storage: Arc<dyn Storage>,
    clock: Arc<dyn Clock>,
    kek: Arc<Kek>,
    public_url: PublicUrl,
    outbound: Arc<OutboundClient>,
}

/// Delivers queued back-channel logout tokens (module docs).
pub struct LogoutDeliveryWorker {
    inner: Arc<Inner>,
    wake: Arc<Notify>,
    /// Rows claimed per batch ([`BATCH_SIZE`]).
    pub batch: u32,
    /// Idle poll interval ([`POLL_INTERVAL`]).
    pub poll: Duration,
    /// Claim lease ([`CLAIM_LEASE`]).
    pub lease: Duration,
}

impl std::fmt::Debug for LogoutDeliveryWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogoutDeliveryWorker")
            .field("batch", &self.batch)
            .field("poll", &self.poll)
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
}

/// The outcome of one POST, mapped from the outbound client's result.
fn outcome_of(result: &Result<u16, OutboundError>) -> DeliveryOutcome {
    match result {
        Ok(status) | Err(OutboundError::Status(status)) => DeliveryOutcome::Status(*status),
        // An URL the policy refuses before connecting (scheme, userinfo, literal address) can
        // never be delivered either.
        Err(OutboundError::Blocked | OutboundError::InvalidUrl) => DeliveryOutcome::Blocked,
        Err(OutboundError::Timeout) => DeliveryOutcome::Timeout,
        Err(OutboundError::Network | OutboundError::TooLarge) => DeliveryOutcome::Network,
    }
}

/// The fixed audit reason of a give-up.
fn reason_of(outcome: DeliveryOutcome, expired: bool) -> &'static str {
    if expired {
        return "expired";
    }
    match outcome {
        DeliveryOutcome::Status(_) => "status",
        DeliveryOutcome::Blocked => "blocked",
        DeliveryOutcome::Network => "network",
        DeliveryOutcome::Timeout => "timeout",
    }
}

impl LogoutDeliveryWorker {
    /// A worker with the production batch size, poll interval and lease. `wake` is
    /// [`crate::state::AppState::logout_wake`]; `outbound` is the application's single outbound
    /// client.
    pub fn new(
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
        kek: Arc<Kek>,
        public_url: PublicUrl,
        outbound: Arc<OutboundClient>,
        wake: Arc<Notify>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                storage,
                clock,
                kek,
                public_url,
                outbound,
            }),
            wake,
            batch: BATCH_SIZE,
            poll: POLL_INTERVAL,
            lease: CLAIM_LEASE,
        }
    }

    /// Claims one batch of due deliveries and attempts each (concurrently).
    pub async fn run_once(&self) -> Result<RunReport, CoreError> {
        let now = self.inner.clock.now();
        let lease = time::Duration::try_from(self.lease).unwrap_or(time::Duration::MINUTE);
        let rows = self
            .inner
            .storage
            .logout()
            .claim_due_deliveries(now + lease, now, self.batch)
            .await?;
        let mut report = RunReport {
            claimed: rows.len(),
            ..RunReport::default()
        };
        let mut tasks = JoinSet::new();
        for row in rows {
            tasks.spawn(Arc::clone(&self.inner).attempt(row));
        }
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(DeliveryResult::Delivered)) => report.delivered += 1,
                Ok(Ok(DeliveryResult::Retry { .. })) => report.retried += 1,
                Ok(Ok(DeliveryResult::GiveUp { .. })) => report.given_up += 1,
                // The row stays leased and is retried after the lease.
                Ok(Err(e)) => tracing::warn!(error = %e, "back-channel logout attempt failed"),
                Err(e) => tracing::error!(error = %e, "back-channel logout task panicked"),
            }
        }
        Ok(report)
    }

    /// Runs until `shutdown` completes: a full batch is followed by the next immediately;
    /// otherwise the worker waits for a logout (the wake), the poll interval or shutdown.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            let full = match self.run_once().await {
                Ok(report) => report.claimed >= self.batch as usize,
                Err(e) => {
                    tracing::warn!(error = %e, "back-channel logout batch failed");
                    false
                }
            };
            if full {
                continue;
            }
            tokio::select! {
                () = &mut shutdown => break,
                () = self.wake.notified() => {}
                () = tokio::time::sleep(self.poll) => {}
            }
        }
    }
}

impl Inner {
    /// One attempt for `row`: prepare, POST, classify, record, audit a give-up.
    async fn attempt(self: Arc<Self>, row: LogoutDelivery) -> Result<DeliveryResult, CoreError> {
        let service = LogoutService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
        };
        let keys = KeyService {
            storage: Arc::clone(&self.storage),
            kek: Arc::clone(&self.kek),
            clock: Arc::clone(&self.clock),
        };
        let prepared = service
            .prepare_delivery(&keys, &self.public_url, &row, self.clock.now())
            .await;
        let (result, reason) = match prepared {
            Ok(prepared) => {
                let body = url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("logout_token", prepared.logout_token.expose_secret())
                    .finish();
                let sent = self.post(&prepared.uri, body).await;
                let now = self.clock.now();
                let outcome = outcome_of(&sent);
                let deadline = row.created_at + LOGOUT_DELIVERY_TTL;
                let mut expired = now >= deadline;
                let mut result = classify_delivery(outcome, row.attempts, row.created_at, now);
                // A retry at or after the deadline would never be claimed (claims require
                // `give_up_at > now`): give up now, so the failure is recorded and audited.
                if let DeliveryResult::Retry {
                    next_attempt_at,
                    error,
                } = &result
                    && *next_attempt_at >= deadline
                {
                    result = DeliveryResult::GiveUp {
                        error: error.clone(),
                    };
                    expired = true;
                }
                (result, reason_of(outcome, expired))
            }
            Err(CoreError::NotFound) => (
                DeliveryResult::GiveUp {
                    error: "client or back-channel logout URI removed".to_owned(),
                },
                "client_removed",
            ),
            Err(e) => {
                tracing::error!(
                    delivery = %row.id,
                    error = %e,
                    "back-channel logout token could not be prepared"
                );
                let now = self.clock.now();
                let next = next_attempt(row.attempts, now);
                let result = if next >= row.created_at + LOGOUT_DELIVERY_TTL {
                    DeliveryResult::GiveUp {
                        error: INTERNAL_ERROR.to_owned(),
                    }
                } else {
                    DeliveryResult::Retry {
                        next_attempt_at: next,
                        error: INTERNAL_ERROR.to_owned(),
                    }
                };
                (result, "internal")
            }
        };
        self.storage
            .logout()
            .complete_delivery(row.id, &result, self.clock.now())
            .await?;
        match &result {
            DeliveryResult::Delivered => {
                tracing::debug!(delivery = %row.id, "back-channel logout delivered");
            }
            DeliveryResult::Retry { error, .. } => {
                tracing::info!(delivery = %row.id, error, "back-channel logout will be retried");
            }
            DeliveryResult::GiveUp { error } => {
                tracing::warn!(delivery = %row.id, error, "back-channel logout given up");
                AuditService {
                    storage: Arc::clone(&self.storage),
                    clock: Arc::clone(&self.clock),
                }
                .record(
                    row.tenant_id,
                    AuditActor::system(),
                    AuditAction::BackchannelLogoutFailed,
                    Some(row.id.to_string()),
                    AuditOutcome::Failure,
                    &RequestContext::system(),
                    AuditDetails::delivery(&row.client_id, row.attempts + 1, reason),
                )
                .await?;
            }
        }
        Ok(result)
    }

    /// POSTs `body` to `uri`; the status, or why there is none. The response body is read
    /// (capped) and discarded.
    async fn post(&self, uri: &str, body: String) -> Result<u16, OutboundError> {
        let resp = self
            .outbound
            .post(uri)?
            .form_body(body)
            .send_any_status()
            .await?;
        let status = resp.status().as_u16();
        // The status decides; an oversized or broken body does not change it.
        let _ = read_capped(resp, LIMIT_TOKEN).await;
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_results_map_to_delivery_outcomes() {
        assert_eq!(outcome_of(&Ok(204)), DeliveryOutcome::Status(204));
        assert_eq!(
            outcome_of(&Err(OutboundError::Status(503))),
            DeliveryOutcome::Status(503)
        );
        assert_eq!(
            outcome_of(&Err(OutboundError::Blocked)),
            DeliveryOutcome::Blocked
        );
        assert_eq!(
            outcome_of(&Err(OutboundError::InvalidUrl)),
            DeliveryOutcome::Blocked
        );
        assert_eq!(
            outcome_of(&Err(OutboundError::Timeout)),
            DeliveryOutcome::Timeout
        );
        assert_eq!(
            outcome_of(&Err(OutboundError::Network)),
            DeliveryOutcome::Network
        );
    }

    #[test]
    fn give_up_reasons_are_fixed_strings() {
        assert_eq!(reason_of(DeliveryOutcome::Status(400), false), "status");
        assert_eq!(reason_of(DeliveryOutcome::Blocked, false), "blocked");
        assert_eq!(reason_of(DeliveryOutcome::Status(500), true), "expired");
    }
}
