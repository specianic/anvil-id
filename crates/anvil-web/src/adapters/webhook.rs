//! Webhook delivery (ADM-05): queued lifecycle events POSTed to each subscribed endpoint by a
//! leased background worker with retries, signed with the Standard Webhooks v1 header layout and
//! sent through the single SSRF-guarded [`OutboundClient`]. Cloned from the back-channel logout
//! worker ([`crate::adapters::backchannel`]): same claim/lease, batch and graceful-stop shape.
//!
//! - Deliveries are enqueued by storage inside the audit transaction
//!   ([`anvil_core::service::audit`]). The worker claims due rows installation-wide with a lease
//!   ([`WebhookRepo::claim_due`](anvil_core::ports::WebhookRepo::claim_due)), so concurrent nodes
//!   never deliver the same row twice and a crashed node's rows come back after the lease.
//! - **Lease rule.** A worker claims at most [`WEBHOOK_BATCH`] rows and sends them
//!   [`WEBHOOK_CONCURRENCY`](anvil_core::model::WEBHOOK_CONCURRENCY) at a time, each bounded by [`WEBHOOK_TIMEOUT`], so a batch finishes
//!   well inside [`WEBHOOK_LEASE`] (the model asserts `lease >= ceil(batch / concurrency) x
//!   timeout + 30 s`). A row is never claimed that cannot be sent within one lease.
//! - **Signing at send time.** `webhook-id` = the delivery id (stable across retries, so
//!   receivers dedupe on it), `webhook-timestamp` = unix seconds of this attempt,
//!   `webhook-signature` = `v1,<base64 HMAC-SHA256>` over `"{id}.{timestamp}.{body}"`; during a
//!   rotation window the current and the previous signature, space-separated. The body is the
//!   ids-only JSON payload (`content-type: application/json`).
//! - **Classification** ([`classify_attempt`]): 2xx delivered; 410 fails the delivery and
//!   disables the endpoint (audited `webhook_endpoint_disabled`); 3xx (redirects are never
//!   followed), other 4xx, 5xx, network errors, timeouts and blocked destinations retry per
//!   [`WEBHOOK_RETRY_SCHEDULE`] with up to 10 % jitter, honouring a delta-seconds `Retry-After`
//!   that is longer than the step (capped at the schedule's last step). After the last step the
//!   delivery fails, audited as `webhook_delivery_failed`. Error classes are fixed strings,
//!   never response bodies; the response body is read (capped at 64 KiB) and discarded.
//! - Delivery is at-least-once: a hard kill mid-request can repeat a delivery (same
//!   `webhook-id`). Graceful shutdown lets the current batch finish.
//! - Metric `anvil_webhook_deliveries_total{outcome}` with outcome `delivered`, `retry`,
//!   `failed` or `disabled`.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::error::CoreError;
use anvil_core::model::{
    AuditAction, AuditActor, AuditDetails, AuditOutcome, RequestContext, WEBHOOK_BATCH,
    WEBHOOK_LEASE, WEBHOOK_RETRY_SCHEDULE, WEBHOOK_TIMEOUT, WebhookDelivery, WebhookEndpoint,
    WebhookResult,
};
use anvil_core::ports::{ClaimedWebhookDelivery, Clock, Storage};
use anvil_core::service::audit::AuditService;
use anvil_core::service::webhook::{UrlRefusal, WebhookService, WebhookUrlCheck, signing_keys};
use anvil_jose::Kek;
use anvil_jose::webhook::signature_v1;
use reqwest::header::{HeaderName, HeaderValue, RETRY_AFTER};
use time::OffsetDateTime;
use tokio::task::JoinSet;

use crate::adapters::outbound::{LIMIT_TOKEN, OutboundClient, OutboundError, read_capped};
use crate::observability::WEBHOOK_DELIVERIES_TOTAL;
use crate::state::AppState;

/// Delay between polls.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Largest `Retry-After` honoured (the schedule's last step).
pub const MAX_RETRY_AFTER: Duration = WEBHOOK_RETRY_SCHEDULE[WEBHOOK_RETRY_SCHEDULE.len() - 1];
/// Largest jitter, as a fraction of the schedule step.
const JITTER_FRACTION: f64 = 0.1;

const HEADER_ID: HeaderName = HeaderName::from_static("webhook-id");
const HEADER_TIMESTAMP: HeaderName = HeaderName::from_static("webhook-timestamp");
const HEADER_SIGNATURE: HeaderName = HeaderName::from_static("webhook-signature");

/// The single outbound client is the webhook URL policy: create-time and send-time checks are
/// the same rules.
impl WebhookUrlCheck for OutboundClient {
    fn check(&self, url: &url::Url) -> Result<(), UrlRefusal> {
        self.check_url(url).map_err(|e| match e {
            OutboundError::Blocked => UrlRefusal::Blocked,
            _ => UrlRefusal::Invalid,
        })
    }
}

impl AppState {
    /// The webhook endpoint service on this state's storage, KEK, clock and outbound policy.
    pub fn webhook_service(&self) -> WebhookService {
        WebhookService {
            storage: self.storage_arc(),
            kek: self.kek_arc(),
            clock: self.clock_arc(),
            url_check: self.outbound_arc(),
        }
    }
}

/// What one POST produced: the status and a parsed delta-seconds `Retry-After`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sent {
    pub status: u16,
    pub retry_after: Option<Duration>,
}

/// What one [`WebhookDeliveryWorker::run_once`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunReport {
    pub claimed: usize,
    pub delivered: usize,
    pub retried: usize,
    pub failed: usize,
    pub disabled: usize,
}

/// The fixed error class of a failed attempt.
fn error_class(sent: &Result<Sent, OutboundError>) -> &'static str {
    match sent {
        Ok(Sent { status, .. }) | Err(OutboundError::Status(status)) => match *status {
            300..=399 => "redirect",
            429 => "status_429",
            400..=499 => "status_4xx",
            500..=599 => "status_5xx",
            _ => "status_other",
        },
        // A URL the policy refuses (scheme, userinfo, blocked address) is retried: the next
        // attempt re-checks it, so a corrected DNS record is delivered.
        Err(OutboundError::Blocked | OutboundError::InvalidUrl) => "blocked",
        Err(OutboundError::Timeout) => "timeout",
        Err(OutboundError::Network | OutboundError::TooLarge) => "network",
    }
}

/// Delay before the next attempt after `attempts_before + 1` attempts, or `None` when the
/// schedule is exhausted. `jitter` in `[0, 1)` adds up to 10 % of the step; a longer
/// `Retry-After` wins, capped at [`MAX_RETRY_AFTER`].
pub fn retry_delay(
    attempts_before: u32,
    jitter: f64,
    retry_after: Option<Duration>,
) -> Option<Duration> {
    let step = *WEBHOOK_RETRY_SCHEDULE.get(attempts_before as usize + 1)?;
    let mut delay = step + step.mul_f64(jitter.clamp(0.0, 1.0) * JITTER_FRACTION);
    if let Some(ra) = retry_after {
        delay = delay.max(ra.min(MAX_RETRY_AFTER));
    }
    Some(delay)
}

/// Decides the result of one attempt on a delivery that had `attempts_before` attempts.
pub fn classify_attempt(
    sent: &Result<Sent, OutboundError>,
    attempts_before: u32,
    now: OffsetDateTime,
    jitter: f64,
) -> WebhookResult {
    if let Ok(s) = sent {
        if (200..300).contains(&s.status) {
            return WebhookResult::Delivered {
                http_status: s.status,
            };
        }
        if s.status == 410 {
            return WebhookResult::DisableEndpoint { http_status: 410 };
        }
    }
    let http_status = match sent {
        Ok(s) => Some(s.status),
        Err(OutboundError::Status(s)) => Some(*s),
        Err(_) => None,
    };
    let retry_after = sent.as_ref().ok().and_then(|s| s.retry_after);
    retry_or_give_up(
        attempts_before,
        now,
        jitter,
        retry_after,
        http_status,
        error_class(sent),
    )
}

fn retry_or_give_up(
    attempts_before: u32,
    now: OffsetDateTime,
    jitter: f64,
    retry_after: Option<Duration>,
    http_status: Option<u16>,
    error_class: &'static str,
) -> WebhookResult {
    match retry_delay(attempts_before, jitter, retry_after)
        .and_then(|d| time::Duration::try_from(d).ok())
    {
        Some(delay) => WebhookResult::Retry {
            next_attempt_at: now + delay,
            http_status,
            error_class,
        },
        None => WebhookResult::GiveUp {
            http_status,
            error_class,
        },
    }
}

/// A delta-seconds `Retry-After` (HTTP-dates are ignored: the schedule applies).
fn parse_retry_after(value: Option<&HeaderValue>) -> Option<Duration> {
    let secs: u64 = value?.to_str().ok()?.trim().parse().ok()?;
    Some(Duration::from_secs(secs))
}

fn jitter() -> f64 {
    let b = anvil_jose::encoding::random_bytes::<4>();
    f64::from(u32::from_le_bytes(b)) / (f64::from(u32::MAX) + 1.0)
}

/// The `webhook-signature` value: one `v1,` signature per key, space-separated.
pub fn signature_header(keys: &[impl AsRef<[u8]>], msg_id: &str, ts: i64, body: &[u8]) -> String {
    keys.iter()
        .map(|k| signature_v1(k.as_ref(), msg_id, ts, body))
        .collect::<Vec<_>>()
        .join(" ")
}

struct Inner {
    storage: Arc<dyn Storage>,
    clock: Arc<dyn Clock>,
    kek: Arc<Kek>,
    outbound: Arc<OutboundClient>,
    timeout: Duration,
}

/// Delivers queued webhook events (module docs). Runs on every node.
pub struct WebhookDeliveryWorker {
    inner: Arc<Inner>,
    /// Rows claimed per poll ([`WEBHOOK_BATCH`]).
    pub batch: u32,
    /// Idle poll interval ([`POLL_INTERVAL`]).
    pub poll: Duration,
    /// Claim lease ([`WEBHOOK_LEASE`]).
    pub lease: Duration,
}

impl std::fmt::Debug for WebhookDeliveryWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookDeliveryWorker")
            .field("batch", &self.batch)
            .field("poll", &self.poll)
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
}

impl WebhookDeliveryWorker {
    /// A worker with the production batch, poll interval, lease and request timeout. `outbound`
    /// is the application's single outbound client.
    pub fn new(
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
        kek: Arc<Kek>,
        outbound: Arc<OutboundClient>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                storage,
                clock,
                kek,
                outbound,
                timeout: WEBHOOK_TIMEOUT,
            }),
            batch: u32::try_from(WEBHOOK_BATCH).unwrap_or(8),
            poll: POLL_INTERVAL,
            lease: WEBHOOK_LEASE,
        }
    }

    /// Claims one batch of due deliveries and attempts each concurrently (the batch size equals
    /// the concurrency, so the whole batch is in flight at once).
    pub async fn run_once(&self) -> Result<RunReport, CoreError> {
        let now = self.inner.clock.now();
        let lease = time::Duration::try_from(self.lease).unwrap_or(time::Duration::MINUTE);
        let rows = self
            .inner
            .storage
            .webhooks()
            .claim_due(now + lease, now, self.batch)
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
                Ok(Ok(Some(WebhookResult::Delivered { .. }))) => report.delivered += 1,
                Ok(Ok(Some(WebhookResult::Retry { .. }))) => report.retried += 1,
                Ok(Ok(Some(WebhookResult::GiveUp { .. }))) => report.failed += 1,
                Ok(Ok(Some(WebhookResult::DisableEndpoint { .. }))) => report.disabled += 1,
                // Completed elsewhere meanwhile (lease expired): nothing recorded here.
                Ok(Ok(None)) => {}
                // The row stays leased and is retried after the lease.
                Ok(Err(e)) => tracing::warn!(error = %e, "webhook delivery attempt failed"),
                Err(e) => tracing::error!(error = %e, "webhook delivery task panicked"),
            }
        }
        Ok(report)
    }

    /// Runs until `shutdown` completes: a full batch is followed by the next immediately;
    /// otherwise the worker waits for the poll interval or shutdown. Shutdown is only observed
    /// between batches, so in-flight deliveries finish.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            let full = match self.run_once().await {
                Ok(report) => report.claimed >= self.batch as usize,
                Err(e) => {
                    tracing::warn!(error = %e, "webhook delivery batch failed");
                    false
                }
            };
            if full {
                continue;
            }
            tokio::select! {
                () = &mut shutdown => break,
                () = tokio::time::sleep(self.poll) => {}
            }
        }
    }
}

impl Inner {
    fn audit(&self) -> AuditService {
        AuditService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock),
        }
    }

    /// One attempt: sign, POST, classify, record, audit a give-up or a disable. `None` if the
    /// delivery was no longer pending when the result was recorded.
    async fn attempt(
        self: Arc<Self>,
        row: ClaimedWebhookDelivery,
    ) -> Result<Option<WebhookResult>, CoreError> {
        let ClaimedWebhookDelivery { delivery, endpoint } = row;
        let now = self.clock.now();
        // The payload is parsed and re-serialised once; the signature covers exactly the bytes
        // `json` sends (serde_json is deterministic for one value). Payloads are written by
        // AnvilID, so a parse failure is an internal error like an unopenable secret.
        let prepared = signing_keys(&self.kek, &endpoint, now).and_then(|keys| {
            let value: serde_json::Value = serde_json::from_str(&delivery.payload_json)
                .map_err(|_| CoreError::Internal("webhook payload is not JSON".into()))?;
            Ok((keys, value))
        });
        let result = match prepared {
            Ok((keys, value)) => {
                let sent = self.post(&delivery, &endpoint, &keys, &value, now).await;
                classify_attempt(&sent, delivery.attempts, self.clock.now(), jitter())
            }
            Err(e) => {
                tracing::error!(
                    delivery = %delivery.id,
                    error = %e,
                    "webhook delivery could not be prepared"
                );
                retry_or_give_up(
                    delivery.attempts,
                    self.clock.now(),
                    jitter(),
                    None,
                    None,
                    "internal",
                )
            }
        };
        if !self
            .storage
            .webhooks()
            .complete(delivery.id, &result, self.clock.now())
            .await?
        {
            tracing::info!(delivery = %delivery.id, "webhook delivery was completed elsewhere");
            return Ok(None);
        }
        let outcome = match &result {
            WebhookResult::Delivered { .. } => "delivered",
            WebhookResult::Retry { .. } => "retry",
            WebhookResult::GiveUp { .. } => "failed",
            WebhookResult::DisableEndpoint { .. } => "disabled",
        };
        metrics::counter!(WEBHOOK_DELIVERIES_TOTAL, "outcome" => outcome).increment(1);
        let attempts = delivery.attempts + 1;
        match &result {
            WebhookResult::Delivered { .. } => {
                tracing::debug!(delivery = %delivery.id, "webhook delivered");
            }
            WebhookResult::Retry { error_class, .. } => {
                tracing::info!(delivery = %delivery.id, error_class, "webhook delivery will be retried");
            }
            WebhookResult::GiveUp { error_class, .. } => {
                tracing::warn!(delivery = %delivery.id, error_class, "webhook delivery given up");
                self.audit()
                    .record(
                        endpoint.tenant_id,
                        AuditActor::system(),
                        AuditAction::WebhookDeliveryFailed,
                        Some(endpoint.id.to_string()),
                        AuditOutcome::Failure,
                        &RequestContext::system(),
                        AuditDetails::webhook_endpoint(&endpoint.name)
                            .with(AuditDetails::webhook_event(delivery.event_type))
                            .with(AuditDetails::webhook_delivery(
                                delivery.id,
                                attempts,
                                error_class,
                            )),
                    )
                    .await?;
            }
            WebhookResult::DisableEndpoint { .. } => {
                tracing::warn!(delivery = %delivery.id, "webhook endpoint answered 410; disabled");
                self.audit()
                    .record(
                        endpoint.tenant_id,
                        AuditActor::system(),
                        AuditAction::WebhookEndpointDisabled,
                        Some(endpoint.id.to_string()),
                        AuditOutcome::Success,
                        &RequestContext::system(),
                        AuditDetails::webhook_endpoint(&endpoint.name)
                            .with(AuditDetails::reason("gone"))
                            .with(AuditDetails::webhook_delivery(
                                delivery.id,
                                attempts,
                                "gone",
                            )),
                    )
                    .await?;
            }
        }
        Ok(Some(result))
    }

    /// POSTs the signed payload; the status and `Retry-After`, or why there is none. The
    /// response body is read (capped) and discarded.
    async fn post(
        &self,
        delivery: &WebhookDelivery,
        endpoint: &WebhookEndpoint,
        keys: &[impl AsRef<[u8]>],
        value: &serde_json::Value,
        now: OffsetDateTime,
    ) -> Result<Sent, OutboundError> {
        // Serialising a parsed `Value` cannot fail (string keys only).
        let body = serde_json::to_vec(value).unwrap_or_default();
        let msg_id = delivery.id.to_string();
        let ts = now.unix_timestamp();
        let signature = signature_header(keys, &msg_id, ts, &body);
        let header = |v: &str| HeaderValue::from_str(v).map_err(|_| OutboundError::InvalidUrl);
        let resp = self
            .outbound
            .post(&endpoint.url)?
            .header(HEADER_ID, header(&msg_id)?)
            .header(HEADER_TIMESTAMP, header(&ts.to_string())?)
            .header(HEADER_SIGNATURE, header(&signature)?)
            .json(value)
            .timeout(self.timeout)
            .send_any_status()
            .await?;
        let status = resp.status().as_u16();
        let retry_after = parse_retry_after(resp.headers().get(RETRY_AFTER));
        // The status decides; an oversized or broken body does not change it.
        let _ = read_capped(resp, LIMIT_TOKEN).await;
        Ok(Sent {
            status,
            retry_after,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn ok(status: u16) -> Result<Sent, OutboundError> {
        Ok(Sent {
            status,
            retry_after: None,
        })
    }

    #[test]
    fn success_and_gone_are_terminal() {
        for s in [200, 201, 204, 299] {
            assert_eq!(
                classify_attempt(&ok(s), 0, now(), 0.0),
                WebhookResult::Delivered { http_status: s }
            );
        }
        assert_eq!(
            classify_attempt(&ok(410), 3, now(), 0.0),
            WebhookResult::DisableEndpoint { http_status: 410 }
        );
    }

    #[test]
    fn failures_retry_on_the_schedule_with_fixed_classes() {
        let cases: [(Result<Sent, OutboundError>, Option<u16>, &str); 9] = [
            (ok(302), Some(302), "redirect"),
            (ok(400), Some(400), "status_4xx"),
            (ok(404), Some(404), "status_4xx"),
            (ok(429), Some(429), "status_429"),
            (ok(500), Some(500), "status_5xx"),
            (Err(OutboundError::Timeout), None, "timeout"),
            (Err(OutboundError::Network), None, "network"),
            (Err(OutboundError::Blocked), None, "blocked"),
            (Err(OutboundError::InvalidUrl), None, "blocked"),
        ];
        for (sent, status, class) in cases {
            assert_eq!(
                classify_attempt(&sent, 0, now(), 0.0),
                WebhookResult::Retry {
                    next_attempt_at: now() + time::Duration::seconds(5),
                    http_status: status,
                    error_class: class,
                },
                "{class}"
            );
        }
    }

    #[test]
    fn schedule_steps_jitter_and_exhaustion() {
        assert_eq!(retry_delay(0, 0.0, None), Some(Duration::from_secs(5)));
        assert_eq!(retry_delay(1, 0.0, None), Some(Duration::from_secs(300)));
        // Up to 10 % jitter.
        assert_eq!(retry_delay(1, 0.999_999, None).unwrap().as_secs(), 329);
        assert_eq!(
            retry_delay(8, 0.0, None),
            Some(Duration::from_secs(24 * 3600))
        );
        // The tenth attempt was the last one.
        assert_eq!(retry_delay(9, 0.0, None), None);
        assert_eq!(
            classify_attempt(&ok(503), 9, now(), 0.0),
            WebhookResult::GiveUp {
                http_status: Some(503),
                error_class: "status_5xx",
            }
        );
    }

    #[test]
    fn retry_after_extends_but_never_shortens_and_is_capped() {
        let long = Some(Duration::from_secs(60));
        assert_eq!(retry_delay(0, 0.0, long), Some(Duration::from_secs(60)));
        let short = Some(Duration::from_secs(1));
        assert_eq!(retry_delay(1, 0.0, short), Some(Duration::from_secs(300)));
        let huge = Some(Duration::from_secs(10 * 24 * 3600));
        assert_eq!(retry_delay(0, 0.0, huge), Some(MAX_RETRY_AFTER));
        assert_eq!(
            parse_retry_after(Some(&HeaderValue::from_static(" 120 "))),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            parse_retry_after(Some(&HeaderValue::from_static(
                "Wed, 21 Oct 2015 07:28:00 GMT"
            ))),
            None
        );
        assert_eq!(parse_retry_after(None), None);
    }

    #[test]
    fn jitter_is_in_range() {
        for _ in 0..100 {
            let j = jitter();
            assert!((0.0..1.0).contains(&j), "{j}");
        }
    }

    #[test]
    fn signature_header_lists_every_key() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let one = signature_header(&[a], "msg_1", 1, b"{}");
        assert!(one.starts_with("v1,") && !one.contains(' '));
        let two = signature_header(&[a, b], "msg_1", 1, b"{}");
        let parts: Vec<&str> = two.split(' ').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], one);
        assert_ne!(parts[1], one);
    }
}
