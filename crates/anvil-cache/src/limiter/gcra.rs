//! Route-class GCRA request-rate limiting on top of `governor`.
//!
//! Time comes from the injected `anvil_core` [`Clock`]: [`CoreClock`] adapts it to governor's
//! clock trait by measuring nanoseconds since a fixed origin, so a fake core clock drives the
//! limiter deterministically.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anvil_core::ports::Clock;
use governor::clock::Clock as GovernorClock;
use governor::middleware::NoOpMiddleware;
use governor::nanos::Nanos;
use governor::state::keyed::DashMapStateStore;
use time::OffsetDateTime;

use super::config::LimiterConfig;
use super::types::{Decision, LimitKey, RouteClass};

/// How often (at most) stale keys are dropped from the GCRA state.
pub(crate) const HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(60);

/// Adapter from the core [`Clock`] to governor's clock: nanoseconds since `origin`, saturating
/// at zero if the wall clock steps backwards past the origin.
#[derive(Clone)]
pub(crate) struct CoreClock {
    clock: Arc<dyn Clock>,
    origin: OffsetDateTime,
}

impl CoreClock {
    pub(crate) fn new(clock: Arc<dyn Clock>) -> Self {
        let origin = clock.now();
        Self { clock, origin }
    }

    fn elapsed(&self) -> Duration {
        let d = self.clock.now() - self.origin;
        if d.is_negative() {
            Duration::ZERO
        } else {
            d.unsigned_abs()
        }
    }
}

impl GovernorClock for CoreClock {
    type Instant = Nanos;

    fn now(&self) -> Nanos {
        Nanos::from(self.elapsed())
    }
}

type Keyed =
    governor::RateLimiter<LimitKey, DashMapStateStore<LimitKey>, CoreClock, NoOpMiddleware<Nanos>>;

/// One governor keyed limiter per quota bucket.
pub(crate) struct Gcra {
    clock: CoreClock,
    auth: Keyed,
    token: Keyed,
    token_client: Keyed,
    admin: Keyed,
    default: Keyed,
    /// Elapsed nanoseconds (since the clock origin) of the last housekeeping run.
    last_housekeeping: AtomicU64,
}

impl Gcra {
    pub(crate) fn new(config: &LimiterConfig, clock: CoreClock) -> Self {
        let build =
            |q: super::config::RateQuota| Keyed::dashmap_with_clock(q.to_governor(), clock.clone());
        Self {
            auth: build(config.auth),
            token: build(config.token),
            token_client: build(config.token_client),
            admin: build(config.admin),
            default: build(config.default),
            last_housekeeping: AtomicU64::new(clock.now().as_u64()),
            clock,
        }
    }

    fn bucket(&self, class: RouteClass, key: &LimitKey) -> &Keyed {
        match class {
            RouteClass::Auth => &self.auth,
            RouteClass::Token if matches!(key, LimitKey::Client { .. }) => &self.token_client,
            RouteClass::Token => &self.token,
            RouteClass::Admin => &self.admin,
            RouteClass::Default => &self.default,
        }
    }

    fn all(&self) -> [&Keyed; 5] {
        [
            &self.auth,
            &self.token,
            &self.token_client,
            &self.admin,
            &self.default,
        ]
    }

    /// Consumes one request for `key` in `class`.
    pub(crate) fn check(&self, class: RouteClass, key: &LimitKey) -> Decision {
        self.housekeeping();
        match self.bucket(class, key).check_key(key) {
            Ok(()) => Decision::Allow,
            Err(not_until) => {
                let retry_after = not_until.wait_time_from(self.clock.now());
                Decision::Deny {
                    retry_after: retry_after.max(Duration::from_nanos(1)),
                }
            }
        }
    }

    /// Drops keys whose state is indistinguishable from a fresh one, at most once per
    /// [`HOUSEKEEPING_INTERVAL`]. Returns whether it ran.
    pub(crate) fn housekeeping(&self) -> bool {
        let now = self.clock.now().as_u64();
        let last = self.last_housekeeping.load(Ordering::Acquire);
        let interval = u64::try_from(HOUSEKEEPING_INTERVAL.as_nanos()).unwrap_or(u64::MAX);
        if now.saturating_sub(last) < interval {
            return false;
        }
        // Only one caller wins the interval.
        if self
            .last_housekeeping
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        for limiter in self.all() {
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
        true
    }

    /// Number of keys currently tracked for `class` (both token buckets for `Token`).
    pub(crate) fn tracked_keys(&self, class: RouteClass) -> usize {
        match class {
            RouteClass::Auth => self.auth.len(),
            RouteClass::Token => self.token.len() + self.token_client.len(),
            RouteClass::Admin => self.admin.len(),
            RouteClass::Default => self.default.len(),
        }
    }
}
