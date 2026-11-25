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
