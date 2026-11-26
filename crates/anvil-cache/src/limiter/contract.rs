//! Backend-agnostic rate-limiter contract suite.
//!
//! This file is **test code**: it is not part of the `anvil-cache` library (no `mod contract` in
//! `limiter/mod.rs`, so its fake clock never reaches a production build). Test crates include it
//! with `#[path = "../src/limiter/contract.rs"] mod contract;` and instantiate
//! [`limiter_contract_tests!`] once per backend, the way `storage_contract_tests!` runs the
//! storage contract against both storage backends. The list of tests lives in the macro, so a
//! backend cannot silently skip one.
//!
//! Every test drives time through [`FakeClock`]; backends must take `now` from the injected core
//! clock (the Redis backend passes it to its scripts and never reads Redis `TIME`).
//!
//! # Pinned semantics (what the Redis scripts must reproduce)
//!
//! GCRA, as implemented by governor 0.10 for a quota of `burst = b` refilled every `T`:
//! the stored state is the theoretical arrival time `tat`, starting at `now` for an unknown key;
//! the tolerance is `tau = T * (b - 1)` (not `T * b`); a request is allowed iff
//! `now >= tat - tau`, and then `tat = max(tat, now) + T`. Consequences pinned below:
//! exactly `b` requests pass at once, request `b + 1` is denied with `retry_after == T`, and one
//! request passes again after `T`. A denial does not consume quota.
//!
//! Backoff: `free_attempts` failures are free, then `base * 2^(n - free - 1)` capped at `cap`;
//! a key idle for `2 * cap` (measured from its last failure) is forgotten. The loose
//! (identifier-only) tier is counted per hourly window and never locked. The brute-force gate
//! checks the strict lock first, then the loose threshold (CAPTCHA when available, otherwise a
//! `min(2 * base, cap)` delay).

#![allow(dead_code)]

use std::any::Any;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anvil_cache::limiter::{
    Backoff, Decision, LimitKey, LimiterConfig, RateLimiter, RateQuota, RouteClass,
};
use anvil_core::model::{TenantId, UserId};
use anvil_core::ports::Clock;
use time::OffsetDateTime;

// --- harness ---------------------------------------------------------------------------------

/// A manually advanced core clock (whole microseconds, so both backends see identical times).
pub struct FakeClock(Mutex<OffsetDateTime>);

impl FakeClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(
            OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("valid timestamp"),
        )))
    }

    pub fn advance(&self, by: Duration) {
        let mut t = self.0.lock().expect("clock lock");
        *t += by;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("clock lock")
    }
}

/// A limiter backend under test.
pub struct TestLimiter {
    pub limiter: Arc<dyn RateLimiter>,
    /// Keeps backend resources (containers, connections) alive for the test.
    pub _guard: Box<dyn Any + Send + Sync>,
}

/// Expands one `#[tokio::test]` per contract test inside `mod $module`, each calling
/// `$factory(config, clock).await` for every limiter it needs. Extra attributes (for example
/// `#[ignore = "..."]`) are applied to every test.
macro_rules! limiter_contract_tests {
    ($module:ident, $factory:path $(, #[$attr:meta])* $(,)?) => {
        mod $module {
            crate::contract::limiter_contract_tests!(@each $factory; [$(#[$attr])*];
                // GCRA request rate
                gcra_burst_is_exact_then_denied_for_one_interval,
                gcra_partial_refill_is_exact,
                gcra_idle_time_never_exceeds_the_burst,
                gcra_denial_does_not_consume_quota,
                gcra_keys_are_isolated,
                gcra_route_classes_are_independent,
                gcra_token_client_keys_use_the_client_quota,
                gcra_disabled_allows_everything,
                // progressive backoff
                backoff_free_attempts_then_doubling_lock_capped,
                backoff_reports_remaining_lock_window,
                backoff_success_clears_the_key,
                backoff_forgotten_after_twice_the_cap_idle,
                backoff_keys_are_isolated_by_tier_and_tenant,
                backoff_loose_tier_is_counted_but_never_locked,
                // brute-force gate
                gate_allows_a_clean_key,
                gate_denies_while_the_strict_key_is_locked,
                gate_loose_tier_requires_captcha_or_delay,
                gate_loose_window_restarts_after_an_hour,
                gate_strict_lock_takes_precedence_over_captcha,
                gate_and_backoff_are_off_when_disabled,
            );
        }
    };
    (@each $factory:path; $attrs:tt; $($name:ident),+ $(,)?) => {
        $(
            crate::contract::limiter_contract_tests!(@one $factory; $name; $attrs);
        )+
    };
    (@one $factory:path; $name:ident; [$(#[$attr:meta])*]) => {
        #[tokio::test]
        $(#[$attr])*
        async fn $name() {
            crate::contract::$name($factory).await;
        }
    };
}

pub(crate) use limiter_contract_tests;

async fn build<F, Fut>(make: &F, config: LimiterConfig) -> (TestLimiter, Arc<FakeClock>)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let clock = FakeClock::new();
    let limiter = make(config, clock.clone()).await;
    (limiter, clock)
}

/// Token quota used by the GCRA tests: burst 3, one request every 10 s.
pub fn gcra_config() -> LimiterConfig {
    LimiterConfig {
        token: RateQuota::per_minute(6, 3),
        token_client: RateQuota::per_minute(12, 5),
        auth: RateQuota::per_minute(6, 2),
        admin: RateQuota::per_minute(6, 2),
        default: RateQuota::per_minute(6, 2),
        ..LimiterConfig::default()
    }
}

const T: Duration = Duration::from_secs(10);
const CAP: Duration = Duration::from_secs(15 * 60);

pub fn ip(last: u8) -> LimitKey {
    LimitKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
}

fn ip6(last: u16) -> LimitKey {
    LimitKey::Ip(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0xdb8, 0, 0, 0, 0, 0, last,
    )))
}

pub fn strict(tenant: TenantId, seed: u8) -> LimitKey {
    LimitKey::IdentIp {
        tenant,
        ident: [seed; 32],
        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
    }
}

pub fn loose(tenant: TenantId, seed: u8) -> LimitKey {
    LimitKey::Identifier {
        tenant,
        ident: [seed; 32],
    }
}

fn deny(retry_after: Duration) -> Decision {
    Decision::Deny { retry_after }
}

async fn allow_n(l: &dyn RateLimiter, class: RouteClass, key: &LimitKey, n: u32) {
    for i in 0..n {
        assert_eq!(l.check(class, key).await, Decision::Allow, "request {i}");
    }
}

// --- GCRA ------------------------------------------------------------------------------------

pub async fn gcra_burst_is_exact_then_denied_for_one_interval<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, clock) = build(&make, gcra_config()).await;
    let l = t.limiter.as_ref();
    let key = ip(1);
    allow_n(l, RouteClass::Token, &key, 3).await;
    // Request b + 1 waits exactly one emission interval (tau = T * (b - 1)).
    assert_eq!(l.check(RouteClass::Token, &key).await, deny(T));
    clock.advance(T - Duration::from_millis(1));
    assert_eq!(
        l.check(RouteClass::Token, &key).await,
        deny(Duration::from_millis(1))
    );
    clock.advance(Duration::from_millis(1));
    assert_eq!(l.check(RouteClass::Token, &key).await, Decision::Allow);
    // Only one cell was replenished.
    assert_eq!(l.check(RouteClass::Token, &key).await, deny(T));
}

pub async fn gcra_partial_refill_is_exact<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, clock) = build(&make, gcra_config()).await;
    let l = t.limiter.as_ref();
    let key = ip(2);
    allow_n(l, RouteClass::Token, &key, 3).await;
    // 2.5 intervals later two cells are back, the third is 5 s away.
    clock.advance(Duration::from_secs(25));
    allow_n(l, RouteClass::Token, &key, 2).await;
    assert_eq!(
        l.check(RouteClass::Token, &key).await,
        deny(Duration::from_secs(5))
    );
}

pub async fn gcra_idle_time_never_exceeds_the_burst<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, clock) = build(&make, gcra_config()).await;
    let l = t.limiter.as_ref();
    let key = ip(3);
    allow_n(l, RouteClass::Token, &key, 3).await;
    clock.advance(Duration::from_secs(3_600));
    allow_n(l, RouteClass::Token, &key, 3).await;
    assert_eq!(l.check(RouteClass::Token, &key).await, deny(T));
}

pub async fn gcra_denial_does_not_consume_quota<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, clock) = build(&make, gcra_config()).await;
    let l = t.limiter.as_ref();
    let key = ip(4);
    allow_n(l, RouteClass::Token, &key, 3).await;
    for _ in 0..20 {
        assert_eq!(l.check(RouteClass::Token, &key).await, deny(T));
    }
    clock.advance(T);
    assert_eq!(l.check(RouteClass::Token, &key).await, Decision::Allow);
}

pub async fn gcra_keys_are_isolated<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, _clock) = build(&make, gcra_config()).await;
    let l = t.limiter.as_ref();
    allow_n(l, RouteClass::Token, &ip(5), 3).await;
    assert!(matches!(
        l.check(RouteClass::Token, &ip(5)).await,
        Decision::Deny { .. }
    ));
    // Another IPv4, an IPv6 and non-IP keys keep their own budgets.
    allow_n(l, RouteClass::Token, &ip(6), 3).await;
    allow_n(l, RouteClass::Token, &ip6(5), 3).await;
    let tenant = TenantId::new_v7();
    allow_n(l, RouteClass::Token, &loose(tenant, 5), 3).await;
    allow_n(l, RouteClass::Token, &strict(tenant, 5), 3).await;
    allow_n(l, RouteClass::Token, &strict(TenantId::new_v7(), 5), 3).await;
    let user = LimitKey::User {
        tenant,
        user: UserId::new_v7(),
    };
    allow_n(l, RouteClass::Token, &user, 3).await;
    assert!(matches!(
        l.check(RouteClass::Token, &user).await,
        Decision::Deny { .. }
    ));
}

pub async fn gcra_route_classes_are_independent<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, _clock) = build(&make, gcra_config()).await;
    let l = t.limiter.as_ref();
    let key = ip(7);
    allow_n(l, RouteClass::Token, &key, 3).await;
    assert!(matches!(
        l.check(RouteClass::Token, &key).await,
        Decision::Deny { .. }
    ));
    for class in [RouteClass::Auth, RouteClass::Admin, RouteClass::Default] {
        allow_n(l, class, &key, 2).await;
        assert_eq!(l.check(class, &key).await, deny(T), "{class:?}");
    }
}

pub async fn gcra_token_client_keys_use_the_client_quota<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, _clock) = build(&make, gcra_config()).await;
    let l = t.limiter.as_ref();
    let key = LimitKey::Client {
        tenant: TenantId::new_v7(),
        client_id: "app".into(),
    };
    // token_client: burst 5, one every 5 s.
    allow_n(l, RouteClass::Token, &key, 5).await;
    assert_eq!(
        l.check(RouteClass::Token, &key).await,
        deny(Duration::from_secs(5))
    );
    // Same client id in another tenant is another key.
    let other = LimitKey::Client {
        tenant: TenantId::new_v7(),
        client_id: "app".into(),
    };
    allow_n(l, RouteClass::Token, &other, 5).await;
}

pub async fn gcra_disabled_allows_everything<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let config = LimiterConfig {
        enabled: false,
        ..gcra_config()
    };
    let (t, _clock) = build(&make, config).await;
    let l = t.limiter.as_ref();
    for class in RouteClass::ALL {
        allow_n(l, class, &ip(8), 50).await;
    }
}

// --- progressive backoff ---------------------------------------------------------------------

pub async fn backoff_free_attempts_then_doubling_lock_capped<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, clock) = build(&make, LimiterConfig::default()).await;
    let l = t.limiter.as_ref();
    let key = strict(TenantId::new_v7(), 1);
    for n in 1..=5 {
        let b = l.record_failure(&key).await;
        assert_eq!(
            b,
            Backoff {
                failures: n,
                locked_for: None
            },
            "failure {n} must be free"
        );
        assert_eq!(l.backoff(&key).await, None);
    }
    let mut expected = Duration::from_secs(1);
    for n in 6..=20 {
        let b = l.record_failure(&key).await;
        assert_eq!(
            b,
            Backoff {
                failures: n,
                locked_for: Some(expected.min(CAP))
            },
            "failure {n}"
        );
        assert_eq!(l.backoff(&key).await, Some(expected.min(CAP)));
        // Wait out the lock (always under 2 * cap, so the entry survives).
        clock.advance(expected.min(CAP));
        assert_eq!(l.backoff(&key).await, None);
        expected *= 2;
    }
}

pub async fn backoff_reports_remaining_lock_window<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, clock) = build(&make, LimiterConfig::default()).await;
    let l = t.limiter.as_ref();
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

pub async fn backoff_success_clears_the_key<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, _clock) = build(&make, LimiterConfig::default()).await;
    let l = t.limiter.as_ref();
    let key = strict(TenantId::new_v7(), 2);
    for _ in 0..8 {
        l.record_failure(&key).await;
    }
    assert!(l.backoff(&key).await.is_some());
    l.record_success(&key).await;
    assert_eq!(l.backoff(&key).await, None);
    assert_eq!(
        l.record_failure(&key).await,
        Backoff {
            failures: 1,
            locked_for: None
        }
    );
}

pub async fn backoff_forgotten_after_twice_the_cap_idle<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, clock) = build(&make, LimiterConfig::default()).await;
    let l = t.limiter.as_ref();
    let tenant = TenantId::new_v7();
    let key = strict(tenant, 3);
    for _ in 0..30 {
        l.record_failure(&key).await;
    }
    assert_eq!(l.backoff(&key).await, Some(CAP));
    // Never a permanent lock.
    clock.advance(CAP);
    assert_eq!(l.backoff(&key).await, None);
    assert_eq!(
        l.brute_force_gate(&key, &loose(tenant, 3), false).await,
        Decision::Allow
    );
    // Just before 2 * cap idle the count is remembered: the next failure locks for the cap.
    clock.advance(CAP - Duration::from_secs(1));
    assert_eq!(
        l.record_failure(&key).await,
        Backoff {
            failures: 31,
            locked_for: Some(CAP)
        }
    );
    // 2 * cap after that failure the entry is gone and counting restarts.
    clock.advance(CAP * 2);
    assert_eq!(l.backoff(&key).await, None);
    assert_eq!(
        l.record_failure(&key).await,
        Backoff {
            failures: 1,
            locked_for: None
        }
    );
}

pub async fn backoff_keys_are_isolated_by_tier_and_tenant<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, _clock) = build(&make, LimiterConfig::default()).await;
    let l = t.limiter.as_ref();
    let tenant = TenantId::new_v7();
    for _ in 0..10 {
        l.record_failure(&strict(tenant, 1)).await;
    }
    assert!(l.backoff(&strict(tenant, 1)).await.is_some());
    assert_eq!(l.backoff(&strict(tenant, 2)).await, None);
    assert_eq!(l.backoff(&strict(TenantId::new_v7(), 1)).await, None);
    // The strict tier's failures are not the loose tier's: same identifier, own count.
    assert_eq!(l.record_failure(&loose(tenant, 1)).await.failures, 1);
    assert_eq!(l.record_failure(&ip(9)).await.failures, 1);
}

pub async fn backoff_loose_tier_is_counted_but_never_locked<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, _clock) = build(&make, LimiterConfig::default()).await;
    let l = t.limiter.as_ref();
    let key = loose(TenantId::new_v7(), 4);
    for n in 1..=60 {
        assert_eq!(
            l.record_failure(&key).await,
            Backoff {
                failures: n,
                locked_for: None
            }
        );
    }
    assert_eq!(l.backoff(&key).await, None);
}

// --- brute-force gate ------------------------------------------------------------------------

pub async fn gate_allows_a_clean_key<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, _clock) = build(&make, LimiterConfig::default()).await;
    let tenant = TenantId::new_v7();
    for captcha in [true, false] {
        assert_eq!(
            t.limiter
                .brute_force_gate(&strict(tenant, 1), &loose(tenant, 1), captcha)
                .await,
            Decision::Allow
        );
    }
}

pub async fn gate_denies_while_the_strict_key_is_locked<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let (t, clock) = build(&make, LimiterConfig::default()).await;
    let l = t.limiter.as_ref();
    let tenant = TenantId::new_v7();
    for _ in 0..8 {
        l.record_failure(&strict(tenant, 1)).await;
    }
    // 8th failure: 4 s lock.
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 1), &loose(tenant, 1), true)
            .await,
        deny(Duration::from_secs(4))
    );
    clock.advance(Duration::from_millis(2_500));
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 1), &loose(tenant, 1), false)
            .await,
        deny(Duration::from_millis(1_500))
    );
    clock.advance(Duration::from_millis(1_500));
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 1), &loose(tenant, 1), true)
            .await,
        Decision::Allow
    );
}

pub async fn gate_loose_tier_requires_captcha_or_delay<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let config = LimiterConfig {
        loose_threshold_per_hour: 10,
        ..LimiterConfig::default()
    };
    let (t, _clock) = build(&make, config).await;
    let l = t.limiter.as_ref();
    let tenant = TenantId::new_v7();
    let lk = loose(tenant, 5);
    for _ in 0..9 {
        l.record_failure(&lk).await;
    }
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 5), &lk, true).await,
        Decision::Allow
    );
    l.record_failure(&lk).await; // 10th within the hour
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 5), &lk, true).await,
        Decision::RequireCaptcha
    );
    // Without CAPTCHA: a short delay of min(2 * base, cap).
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 5), &lk, false).await,
        deny(Duration::from_secs(2))
    );
}

pub async fn gate_loose_window_restarts_after_an_hour<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let config = LimiterConfig {
        loose_threshold_per_hour: 5,
        // Keep the loose entry alive across the hour (idle expiry is 2 * cap).
        cap: Duration::from_secs(3_600),
        ..LimiterConfig::default()
    };
    let (t, clock) = build(&make, config).await;
    let l = t.limiter.as_ref();
    let tenant = TenantId::new_v7();
    let lk = loose(tenant, 6);
    for _ in 0..5 {
        l.record_failure(&lk).await;
    }
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 6), &lk, true).await,
        Decision::RequireCaptcha
    );
    clock.advance(Duration::from_secs(3_599));
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 6), &lk, true).await,
        Decision::RequireCaptcha
    );
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 6), &lk, true).await,
        Decision::Allow
    );
    // The next failure opens a fresh window counting from one.
    assert_eq!(l.record_failure(&lk).await.failures, 1);
}

pub async fn gate_strict_lock_takes_precedence_over_captcha<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let config = LimiterConfig {
        loose_threshold_per_hour: 10,
        ..LimiterConfig::default()
    };
    let (t, _clock) = build(&make, config).await;
    let l = t.limiter.as_ref();
    let tenant = TenantId::new_v7();
    for _ in 0..10 {
        l.record_failure(&loose(tenant, 7)).await;
    }
    for _ in 0..6 {
        l.record_failure(&strict(tenant, 7)).await;
    }
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 7), &loose(tenant, 7), true)
            .await,
        deny(Duration::from_secs(1))
    );
}

pub async fn gate_and_backoff_are_off_when_disabled<F, Fut>(make: F)
where
    F: Fn(LimiterConfig, Arc<FakeClock>) -> Fut,
    Fut: Future<Output = TestLimiter>,
{
    let config = LimiterConfig {
        enabled: false,
        loose_threshold_per_hour: 5,
        ..LimiterConfig::default()
    };
    let (t, _clock) = build(&make, config).await;
    let l = t.limiter.as_ref();
    let tenant = TenantId::new_v7();
    for _ in 0..20 {
        assert_eq!(
            l.record_failure(&strict(tenant, 1)).await,
            Backoff {
                failures: 0,
                locked_for: None
            }
        );
        l.record_failure(&loose(tenant, 1)).await;
    }
    assert_eq!(l.backoff(&strict(tenant, 1)).await, None);
    assert_eq!(
        l.brute_force_gate(&strict(tenant, 1), &loose(tenant, 1), true)
            .await,
        Decision::Allow
    );
}
