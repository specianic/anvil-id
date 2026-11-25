//! Deterministic tests for the single rate limiter (ARCHITECTURE §11).
//!
//! Every test drives time through a fake `anvil_core` clock; nothing sleeps.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anvil_cache::limiter::{
    Decision, InProcessLimiter, LimitKey, LimiterConfig, RateLimiter, RateQuota, RouteClass,
};
use anvil_core::model::TenantId;
use anvil_core::ports::Clock;
use time::OffsetDateTime;

// --- support ---------------------------------------------------------------------------------

struct TestClock(Mutex<OffsetDateTime>);

impl TestClock {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(
            OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        )))
    }

    fn advance(&self, by: Duration) {
        let mut t = self.0.lock().unwrap();
        *t += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

fn limiter_with(config: LimiterConfig) -> (InProcessLimiter, Arc<TestClock>) {
    let clock = TestClock::new();
    let limiter = InProcessLimiter::new(config, clock.clone());
    (limiter, clock)
}

fn limiter() -> (InProcessLimiter, Arc<TestClock>) {
    limiter_with(LimiterConfig::default())
}

fn ip(last: u8) -> LimitKey {
    LimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
}

fn ip_n(n: u32) -> LimitKey {
    let [_, b, c, d] = n.to_be_bytes();
    LimitKey::Ip(IpAddr::V4(Ipv4Addr::new(10, b, c, d)))
}

fn retry_after(d: Decision) -> Duration {
    match d {
        Decision::Deny { retry_after } => retry_after,
        other => panic!("expected Deny, got {other:?}"),
    }
}

// --- GCRA (Task 1) ---------------------------------------------------------------------------

#[test]
fn gcra_defaults_match_the_documented_quotas() {
    let c = LimiterConfig::default();
    assert!(c.enabled);
    assert_eq!(c.auth, RateQuota::per_minute(10, 5));
    assert_eq!(c.token, RateQuota::per_second(50, 50));
    assert_eq!(c.token_client, RateQuota::per_second(100, 100));
    assert_eq!(c.admin, RateQuota::per_second(20, 20));
    assert_eq!(c.default, RateQuota::per_second(50, 50));
    assert_eq!(c.free_attempts, 5);
    assert_eq!(c.base, Duration::from_secs(1));
    assert_eq!(c.cap, Duration::from_secs(15 * 60));
    assert_eq!(c.loose_threshold_per_hour, 50);
}

#[tokio::test]
async fn gcra_auth_burst_exhausted_then_denied_with_retry_after() {
    let (l, clock) = limiter();
    for i in 0..5 {
        assert_eq!(
            l.check(RouteClass::Auth, &ip(1)).await,
            Decision::Allow,
            "request {i}"
        );
    }
    let wait = retry_after(l.check(RouteClass::Auth, &ip(1)).await);
    assert!(wait > Duration::ZERO);
    // 10/min replenishes one cell every 6 s.
    assert!(wait <= Duration::from_secs(6), "{wait:?}");

    // A different IP is unaffected.
    assert_eq!(l.check(RouteClass::Auth, &ip(2)).await, Decision::Allow);

    // Still denied just before the window; allowed once retry_after has elapsed.
    clock.advance(wait - Duration::from_millis(1));
    assert!(matches!(
        l.check(RouteClass::Auth, &ip(1)).await,
        Decision::Deny { .. }
    ));
    clock.advance(Duration::from_millis(1));
    assert_eq!(l.check(RouteClass::Auth, &ip(1)).await, Decision::Allow);
}

#[tokio::test]
async fn gcra_route_classes_are_independent() {
    let (l, _clock) = limiter();
    let key = ip(7);
    for _ in 0..50 {
        assert_eq!(l.check(RouteClass::Token, &key).await, Decision::Allow);
    }
    assert!(matches!(
        l.check(RouteClass::Token, &key).await,
        Decision::Deny { .. }
    ));
    // Token exhaustion does not touch Auth, Admin or Default for the same IP.
    assert_eq!(l.check(RouteClass::Auth, &key).await, Decision::Allow);
    assert_eq!(l.check(RouteClass::Admin, &key).await, Decision::Allow);
    assert_eq!(l.check(RouteClass::Default, &key).await, Decision::Allow);
}

#[tokio::test]
async fn gcra_token_client_keys_use_the_client_quota() {
    let (l, _clock) = limiter();
    let key = LimitKey::Client {
        tenant: TenantId::new_v7(),
        client_id: "app".into(),
    };
    for i in 0..100 {
        assert_eq!(
            l.check(RouteClass::Token, &key).await,
            Decision::Allow,
            "request {i}"
        );
    }
    assert!(matches!(
        l.check(RouteClass::Token, &key).await,
        Decision::Deny { .. }
    ));
}

#[tokio::test]
async fn gcra_custom_quota_is_honoured() {
    let config = LimiterConfig {
        admin: RateQuota::per_second(1, 2),
        ..LimiterConfig::default()
    };
    let (l, clock) = limiter_with(config);
    assert_eq!(l.check(RouteClass::Admin, &ip(1)).await, Decision::Allow);
    assert_eq!(l.check(RouteClass::Admin, &ip(1)).await, Decision::Allow);
    let wait = retry_after(l.check(RouteClass::Admin, &ip(1)).await);
    assert!(wait > Duration::ZERO && wait <= Duration::from_secs(1));
    clock.advance(wait);
    assert_eq!(l.check(RouteClass::Admin, &ip(1)).await, Decision::Allow);
}

#[tokio::test]
async fn gcra_disabled_allows_everything() {
    let config = LimiterConfig {
        enabled: false,
        ..LimiterConfig::default()
    };
    let (l, _clock) = limiter_with(config);
    for _ in 0..1_000 {
        assert_eq!(l.check(RouteClass::Auth, &ip(1)).await, Decision::Allow);
    }
}

#[tokio::test]
async fn gcra_housekeeping_drops_stale_keys_at_most_once_per_minute() {
    let (l, clock) = limiter();
    for n in 0..200 {
        assert_eq!(
            l.check(RouteClass::Default, &ip_n(n)).await,
            Decision::Allow
        );
    }
    assert_eq!(l.tracked_keys(RouteClass::Default), 200);

    // 61 s later every key's window has passed; the next check triggers housekeeping.
    clock.advance(Duration::from_secs(61));
    l.check(RouteClass::Default, &ip_n(10_000)).await;
    assert!(
        l.tracked_keys(RouteClass::Default) <= 1,
        "{}",
        l.tracked_keys(RouteClass::Default)
    );

    // A fresh batch of keys, then 30 s: housekeeping must not run again yet.
    for n in 0..100 {
        l.check(RouteClass::Default, &ip_n(20_000 + n)).await;
    }
    clock.advance(Duration::from_secs(30));
    l.check(RouteClass::Default, &ip_n(30_000)).await;
    assert!(l.tracked_keys(RouteClass::Default) >= 100);

    // Past the 60 s interval it runs and the stale batch is dropped.
    clock.advance(Duration::from_secs(31));
    l.check(RouteClass::Default, &ip_n(40_000)).await;
    assert!(
        l.tracked_keys(RouteClass::Default) <= 1,
        "{}",
        l.tracked_keys(RouteClass::Default)
    );
}

#[tokio::test]
async fn gcra_housekeeping_never_resets_an_active_denial() {
    let (l, clock) = limiter();
    // Exhaust ip(4) at +59 s (before the first housekeeping interval elapses).
    clock.advance(Duration::from_secs(59));
    for _ in 0..5 {
        assert_eq!(l.check(RouteClass::Auth, &ip(4)).await, Decision::Allow);
    }
    // At +61 s housekeeping runs (triggered by another key); ip(4) is still inside its window
    // (10/min burst 5: ~30 s of debt), so it must be retained and still denied.
    clock.advance(Duration::from_secs(2));
    assert_eq!(l.check(RouteClass::Auth, &ip(5)).await, Decision::Allow);
    assert_eq!(l.tracked_keys(RouteClass::Auth), 2);
    assert!(matches!(
        l.check(RouteClass::Auth, &ip(4)).await,
        Decision::Deny { .. }
    ));
}

// --- progressive backoff and brute-force gate (Task 2) ---------------------------------------

fn ident(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn strict(tenant: TenantId, seed: u8) -> LimitKey {
    LimitKey::IdentIp { tenant, ident: ident(seed), ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)) }
}

fn loose(tenant: TenantId, seed: u8) -> LimitKey {
    LimitKey::Identifier { tenant, ident: ident(seed) }
}

const CAP: Duration = Duration::from_secs(15 * 60);

#[tokio::test]
async fn backoff_free_attempts_then_doubling_lock_capped_at_fifteen_minutes() {
    let (l, clock) = limiter();
    let key = strict(TenantId::new_v7(), 1);
    for n in 1..=5 {
        let b = l.record_failure(&key).await;
        assert_eq!(b.failures, n);
        assert_eq!(b.locked_for, None, "failure {n} must be free");
        assert_eq!(l.backoff(&key).await, None);
    }
    let mut expected = Duration::from_secs(1);
    for n in 6..=20 {
        let b = l.record_failure(&key).await;
        assert_eq!(b.failures, n);
        assert_eq!(b.locked_for, Some(expected.min(CAP)), "failure {n}");
        assert_eq!(l.backoff(&key).await, Some(expected.min(CAP)));
        expected *= 2;
        // Wait out the lock (always well under 2·cap, so the entry survives).
        clock.advance(expected.min(CAP) / 2);
        clock.advance(expected.min(CAP) / 2);
    }
}

#[tokio::test]
async fn backoff_reports_remaining_lock_window() {
    let (l, clock) = limiter();
    let key = ip(1);
    for _ in 0..7 {
        l.record_failure(&key).await;
    }
    assert_eq!(l.backoff(&key).await, Some(Duration::from_secs(2)));
    clock.advance(Duration::from_millis(1_500));
    assert_eq!(l.backoff(&key).await, Some(Duration::from_millis(500)));
    clock.advance(Duration::from_millis(500));
    assert_eq!(l.backoff(&key).await, None);
}

#[tokio::test]
async fn backoff_success_clears_the_key() {
    let (l, _clock) = limiter();
    let key = strict(TenantId::new_v7(), 2);
    for _ in 0..8 {
        l.record_failure(&key).await;
    }
    assert!(l.backoff(&key).await.is_some());
    l.record_success(&key).await;
    assert_eq!(l.backoff(&key).await, None);
    assert_eq!(l.record_failure(&key).await.failures, 1);
}

#[tokio::test]
async fn backoff_entry_expires_after_twice_the_cap_of_inactivity() {
    let (l, clock) = limiter();
    let key = strict(TenantId::new_v7(), 3);
    for _ in 0..30 {
        l.record_failure(&key).await;
    }
    assert_eq!(l.backoff(&key).await, Some(CAP));

    // Never a permanent lock: after the cap window the key is usable again.
    clock.advance(CAP);
    assert_eq!(l.backoff(&key).await, None);
    let gate = l.brute_force_gate(&key, &loose(TenantId::new_v7(), 3), false).await;
    assert_eq!(gate, Decision::Allow);

    // Just before 2·cap idle the failure count is still remembered...
    clock.advance(CAP - Duration::from_secs(1));
    assert_eq!(l.backoff(&key).await, None);
    // ...after 2·cap idle the entry is gone and counting restarts at zero.
    clock.advance(Duration::from_secs(1));
    assert_eq!(l.backoff(&key).await, None);
    assert_eq!(l.record_failure(&key).await, anvil_cache::limiter::Backoff {
        failures: 1,
        locked_for: None
    });
}

#[tokio::test]
async fn backoff_keys_are_independent() {
    let (l, _clock) = limiter();
    let tenant = TenantId::new_v7();
    for _ in 0..10 {
        l.record_failure(&strict(tenant, 1)).await;
    }
    assert!(l.backoff(&strict(tenant, 1)).await.is_some());
    assert_eq!(l.backoff(&strict(tenant, 2)).await, None);
    assert_eq!(l.backoff(&strict(TenantId::new_v7(), 1)).await, None);
}

#[tokio::test]
async fn gate_allows_a_clean_key() {
    let (l, _clock) = limiter();
    let t = TenantId::new_v7();
    assert_eq!(l.brute_force_gate(&strict(t, 1), &loose(t, 1), true).await, Decision::Allow);
}

#[tokio::test]
async fn gate_denies_while_the_strict_key_is_locked() {
    let (l, clock) = limiter();
    let t = TenantId::new_v7();
    for _ in 0..8 {
        l.record_failure(&strict(t, 1)).await;
    }
    // 8th failure: 4 s lock.
    let wait = retry_after(l.brute_force_gate(&strict(t, 1), &loose(t, 1), true).await);
    assert_eq!(wait, Duration::from_secs(4));
    clock.advance(Duration::from_secs(4));
    assert_eq!(l.brute_force_gate(&strict(t, 1), &loose(t, 1), true).await, Decision::Allow);
}

#[tokio::test]
async fn gate_loose_tier_requires_captcha_or_delays_once_over_the_hourly_threshold() {
    let (l, clock) = limiter();
    let t = TenantId::new_v7();
    let lk = loose(t, 5);
    // 49 failures from "many IPs": the loose tier is counted but never locked.
    for _ in 0..49 {
        let b = l.record_failure(&lk).await;
        assert_eq!(b.locked_for, None);
    }
    assert_eq!(l.backoff(&lk).await, None);
    assert_eq!(l.brute_force_gate(&strict(t, 5), &lk, true).await, Decision::Allow);

    l.record_failure(&lk).await; // 50th within the hour
    assert_eq!(l.brute_force_gate(&strict(t, 5), &lk, true).await, Decision::RequireCaptcha);
    let delay = retry_after(l.brute_force_gate(&strict(t, 5), &lk, false).await);
    assert!(delay > Duration::ZERO && delay <= Duration::from_secs(2), "{delay:?}");

    // A new hourly window starts clean.
    clock.advance(Duration::from_secs(3_600));
    assert_eq!(l.brute_force_gate(&strict(t, 5), &lk, true).await, Decision::Allow);
}

#[tokio::test]
async fn gate_strict_lock_takes_precedence_over_captcha() {
    let (l, _clock) = limiter();
    let t = TenantId::new_v7();
    for _ in 0..50 {
        l.record_failure(&loose(t, 6)).await;
    }
    for _ in 0..6 {
        l.record_failure(&strict(t, 6)).await;
    }
    assert_eq!(
        l.brute_force_gate(&strict(t, 6), &loose(t, 6), true).await,
        Decision::Deny { retry_after: Duration::from_secs(1) }
    );
}

#[tokio::test]
async fn gate_known_and_unknown_identifiers_behave_identically() {
    // The limiter only ever sees hashes, so two identifiers (one standing for an existing
    // account, one for a non-existent one) must produce identical outcomes step by step.
    let (l, _clock) = limiter();
    let t = TenantId::new_v7();
    let (known, unknown) = (7u8, 8u8);
    for _ in 0..60 {
        let a = l.record_failure(&strict(t, known)).await;
        let b = l.record_failure(&strict(t, unknown)).await;
        assert_eq!(a, b);
        let la = l.record_failure(&loose(t, known)).await;
        let lb = l.record_failure(&loose(t, unknown)).await;
        assert_eq!(la, lb);
        assert_eq!(
            l.brute_force_gate(&strict(t, known), &loose(t, known), true).await,
            l.brute_force_gate(&strict(t, unknown), &loose(t, unknown), true).await,
        );
    }
}

#[tokio::test]
async fn gate_and_backoff_are_off_when_disabled() {
    let config = LimiterConfig { enabled: false, ..LimiterConfig::default() };
    let (l, _clock) = limiter_with(config);
    let t = TenantId::new_v7();
    for _ in 0..100 {
        assert_eq!(l.record_failure(&strict(t, 1)).await.locked_for, None);
        l.record_failure(&loose(t, 1)).await;
    }
    assert_eq!(l.backoff(&strict(t, 1)).await, None);
    assert_eq!(l.brute_force_gate(&strict(t, 1), &loose(t, 1), true).await, Decision::Allow);
}

#[tokio::test]
async fn limiter_is_usable_as_a_trait_object() {
    let (l, _clock) = limiter();
    let dynamic: Arc<dyn RateLimiter> = Arc::new(l);
    assert_eq!(dynamic.check(RouteClass::Default, &ip(1)).await, Decision::Allow);
    assert_eq!(dynamic.record_failure(&ip(1)).await.failures, 1);
}
