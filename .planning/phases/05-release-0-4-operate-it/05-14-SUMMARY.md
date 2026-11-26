---
phase: 05-release-0-4-operate-it
plan: 14
subsystem: webhooks
tags: [webhooks, standard-webhooks, hmac, outbound, ssrf, lease, worker, audit, metrics]

requires:
  - phase: 05-release-0-4-operate-it
    provides: 05-01 model (WEBHOOK_BATCH/CONCURRENCY/TIMEOUT/LEASE, WEBHOOK_RETRY_SCHEDULE, WEBHOOK_SECRET_PURPOSE, webhook_aad), 05-02 WebhookRepo, 05-05 BackgroundWorker + metric names, 05-06/05-07 backends (enqueue in AuditRepo::append, leased claim_due), 05-10 policy::webhook_event + anvil_jose::webhook
provides:
  - anvil_core::service::webhook (WebhookService, WebhookUrlCheck, UrlRefusal, NewWebhookInput, EndpointWithSecret, signing_keys, seal_webhook_secret, validate_webhook_{name,url,events}, WEBHOOK_ROTATION_GRACE)
  - AuditService::record computes NewAuditEvent.webhook (enqueue in the audit transaction)
  - anvil_web::adapters::webhook (WebhookDeliveryWorker, RunReport, classify_attempt, retry_delay, signature_header, Sent, POLL_INTERVAL, MAX_RETRY_AFTER)
  - impl WebhookUrlCheck for OutboundClient; AppState::webhook_service()
  - startup pushes the worker into Started.workers (BackgroundWorker name "webhook_delivery")
affects: [05-23, 05-24, 05-25, 05-27, 05-28]

tech-stack:
  added: []
  patterns:
    - "Core takes the outbound URL policy as a trait (WebhookUrlCheck) implemented by the web layer's single OutboundClient, so create-time and send-time checks are the same rules and core stays free of anvil-web"
    - "Signature covers exactly the bytes sent: payload parsed once, signed over serde_json::to_vec(value), sent with OutboundRequest::json(value)"
    - "BackgroundWorker impl for an anvil-web worker lives in startup.rs (jobs.rs not owned; orphan rule satisfied by the local trait)"

key-files:
  created:
    - crates/anvil-web/tests/webhooks.rs
    - crates/anvil-web/tests/security_webhooks.rs
    - crates/anvil-web/tests/webhook_support/mod.rs
    - crates/anvilid/tests/webhook_worker.rs
  modified:
    - crates/anvil-core/src/service/webhook.rs
    - crates/anvil-core/src/service/audit.rs
    - crates/anvil-web/src/adapters/webhook.rs
    - crates/anvilid/src/startup.rs

key-decisions:
  - "Payload data.tenant is the tenant id, not the slug: AuditService::record only has the id; a slug lookup would add a read to every sign-in and panic the session-service test fake. Logged in deferred-items for the webhook_event doc owner"
  - "The sealed plaintext is the whole whsec_ string; signing_keys opens it and parses it with parse_webhook_secret (the HMAC key is the decoded part)"
  - "Endpoint name rule ^[a-z0-9][a-z0-9_-]{0,63}$ (declarative-config key); events sorted and deduplicated, non-empty, never `test`"
  - "Blocked/invalid destinations at send time retry (class `blocked`) rather than give up: each attempt re-checks the URL, so a corrected DNS record recovers; the schedule bounds it"
  - "Retry delay = schedule step + up to 10 % jitter; a delta-seconds Retry-After longer than that wins, capped at the last step (24 h); HTTP-date Retry-After is ignored"
  - "Give-up audit: webhook_delivery_failed, system actor, target = endpoint id, details endpoint name, event_type, delivery_id, attempts, error_class. 410: webhook_endpoint_disabled with reason gone"
  - "complete() returning false (completed elsewhere after a lease expiry) records no audit and no metric"
  - "WebhookService.create accepts an optional caller-provided whsec_ secret (for the declarative config apply); validated with parse_webhook_secret"

patterns-established: []

requirements-completed: [ADM-05, OPS-03]

duration: ~25min
completed: 2026-11-26
---

# Phase 5 Plan 14: Webhook service and delivery worker Summary

**Signed, retried webhooks: lifecycle audit events enqueue ids-only deliveries in the audit transaction, a leased WebhookDeliveryWorker (cloned from the back-channel worker) signs each attempt with Standard Webhooks v1 headers and sends it through the single OutboundClient, and WebhookService manages endpoints with KEK-sealed `whsec_` secrets that are shown exactly once.**

## Delivery request

- `POST {endpoint.url}`, `content-type: application/json`, body = the ids-only payload
  (`{"type","timestamp","data":{"tenant","user_id"/"session_id"/"client_id","actor"}}`).
- `webhook-id`: the delivery id (stable across retries; redelivery makes a new id).
- `webhook-timestamp`: unix seconds of this attempt (signed at send time).
- `webhook-signature`: `v1,<base64 HMAC-SHA256(key, "{id}.{ts}.{body}")>`; during the 24 h
  rotation window `v1,<new> v1,<previous>` (space-separated, new first).
- Timeout 15 s (`WEBHOOK_TIMEOUT`), redirects never followed, response body read capped at
  64 KiB and discarded.

## Classification and retry schedule

| Result | Outcome |
|--------|---------|
| 2xx | Delivered |
| 410 | delivery Failed, endpoint disabled (`disabled_reason = gone`), audited `webhook_endpoint_disabled` |
| 3xx (`redirect`), 429 (`status_429`), other 4xx (`status_4xx`), 5xx (`status_5xx`), `network`, `timeout`, `blocked` | Retry |
| 10th attempt failed | Failed, audited `webhook_delivery_failed` |
| secret/payload unusable | Retry/give-up with class `internal` |

Delays between attempts (`WEBHOOK_RETRY_SCHEDULE`): immediately, 5 s, 5 min, 30 min, 2 h, 5 h,
10 h, 14 h, 20 h, 24 h (10 attempts, about 3 days), each plus up to 10 % jitter; `Retry-After`
(delta seconds) extends a step up to 24 h. Metric `anvil_webhook_deliveries_total{outcome}`:
`delivered`, `retry`, `failed`, `disabled`.

Worker: claims `WEBHOOK_BATCH` (8) rows with `next_attempt_at = now + WEBHOOK_LEASE` (45 s),
sends all 8 concurrently (`WEBHOOK_CONCURRENCY` = 8), polls every 2 s, a full batch is followed
immediately, shutdown is observed between batches.

## Service

`WebhookService { storage, kek, clock, url_check }`: `list`, `get`, `create` (returns
`EndpointWithSecret` once), `update` (fields audited), `rotate_secret` (new secret once,
previous kept until now + 24 h), `delete`, `send_test` (`test` event, ignores subscriptions,
audited `webhook_test_sent`), `redeliver` (new delivery, audited `webhook_redelivered`),
`deliveries` (admin page rules), `signing_keys`. 05-23 gets it from `AppState::webhook_service()`.

## Task Commits

1. **Task 1: WebhookService and enqueue from AuditService:** `363bb2a` (feat)
2. **Task 2: delivery worker, classification, startup wiring, tests:** `558a2eb` (feat)
3. Deferred items: `3097df9` (docs)

## Tests

- `anvil-core --lib service::webhook` (6): name/url/events validation, sealed secret opens only for its endpoint and KEK, previous secret only inside the window, provided secrets must be whsec.
- `anvil-web --lib adapters::webhook` (6): terminal results, retry classes, schedule/jitter/exhaustion, Retry-After extend/cap/parse, jitter range, signature header.
- `anvil-web --test webhooks` (13): `service_create_returns_secret_once_and_stores_it_sealed`, `service_refuses_loopback_and_plain_http_in_production`, `service_user_created_via_admin_api_enqueues_one_delivery` (subscribed 1, unsubscribed 0, disabled 0), `service_failed_or_non_lifecycle_events_enqueue_nothing`, `service_rotate_returns_new_secret_and_keeps_previous_for_24h`, `service_test_send_and_redeliver_are_audited`, `worker_delivers_signed_request_once` (+ metric), `worker_retries_5xx_on_schedule_with_same_id`, `worker_honours_retry_after_on_429`, `worker_410_disables_endpoint_and_audits`, `worker_redirect_is_a_failure_and_retried`, `worker_gives_up_after_schedule_and_audits`, `worker_signs_with_both_secrets_during_rotation_window`.
- `anvil-web --test security_webhooks` (6): `webhook_url_private_ip_refused_at_create`, `webhook_send_blocked_for_private_destination` (host name resolving to loopback, and a literal written behind the service's back), `webhook_secret_never_returned_after_create`, `webhook_payload_has_no_pii`, `webhook_signature_verifies_and_tampered_body_fails`, `webhook_redirect_not_followed`.
- `anvilid --test webhook_worker` (2): `two_workers_deliver_each_row_exactly_once` (27 rows, two concurrent workers), `lease_holds_in_flight_rows_past_the_request_timeout` (sink holds all 8 requests, clock +20 s, the second worker claims 0; bounded by a 5 s timeout so a broken lease fails instead of hanging). Mutation check: with worker A's lease set to 10 s the second test fails.

## Verification

- All suites above green on SQLite. Regression runs: `anvil-core --lib` (763), `anvil-web --test backchannel/admin_audit/sessions/logout/admin_api`, `anvilid --test serve/jobs` all pass.
- `cargo clippy -p anvil-core -p anvil-web -p anvilid --lib --tests --bins`: no warnings in these files (only the pre-existing `serde-saphyr` unused-dependency manifest warning).
- `grep -rn "reqwest::Client" crates/anvil-web/src | grep -v outbound.rs`: empty.
- **Not run:** Postgres variants (`ANVILID_TEST_DB=postgres` for `webhooks`, `security_webhooks`, `webhook_worker`) need Docker; left for CI (`just test-pg`).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Tenant id instead of slug in the payload**
- **Found during:** Task 1
- **Issue:** `webhook_event(tenant_slug, …)` needs a slug, but `AuditService::record` only has the tenant id and the plan forbids new AuditService fields. A per-event tenant lookup costs a read on every sign-in and hits `unreachable!()` in the session-service test fake (not owned).
- **Fix:** pass `tenant.to_string()`; `send_test` does the same for consistency. Logged in deferred-items for the doc owner.
- **Commit:** `363bb2a`

**2. [Rule 3 - Blocking] BackgroundWorker impl in startup.rs**
- jobs.rs is not in this plan's files; the impl for `WebhookDeliveryWorker` sits in startup.rs.
- **Commit:** `558a2eb`

**3. [Rule 3 - Blocking] Zeroizing via `secrecy::zeroize`**
- anvil-core has no direct `zeroize` dependency (manifests belong to 05-01); the re-export from secrecy is used.

**4. Task split of commits**
- The anvil-web test files exercise both the service and the worker (shared support module), so they were committed with Task 2; the Task 1 commit holds the core service and the audit wiring.

## Deferred Issues

- `JOBS_SHUTDOWN_TIMEOUT` (10 s) < `WEBHOOK_TIMEOUT` (15 s); and the `security_webhooks.rs` names need adding to `scripts/check-security-tests.sh` (both in deferred-items.md).

## Self-Check: PASSED
