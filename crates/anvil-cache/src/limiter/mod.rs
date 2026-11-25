//! The one rate limiter of the codebase (ARCHITECTURE §11).
//!
//! - Request rate: GCRA per [`RouteClass`] via `governor`, keyed by [`LimitKey`].
//! - Brute force: progressive backoff per key (free attempts, then `base * 2^n` capped at `cap`,
//!   forgotten after `2 * cap` without failures; never a permanent lock) plus a two-tier gate:
//!   the strict `(identifier, IP)` tier locks, the loose identifier-only tier escalates to
//!   CAPTCHA (or a short delay) once it exceeds an hourly threshold.
//!
//! Time always comes from the injected `anvil_core` clock and nothing here sleeps: callers
//! receive a `retry_after` and decide how to respond. Keyed state is bounded: GCRA keys are
//! pruned at most once per minute (triggered from [`RateLimiter::check`]) and the backoff store
//! is a capacity-bounded cache.

mod backoff;
mod config;
mod gcra;
mod types;

use std::sync::Arc;
use std::time::Duration;

use anvil_core::ports::Clock;
use async_trait::async_trait;

pub use config::{LimiterConfig, RateQuota};
pub use types::{Backoff, Decision, LimitKey, RouteClass};

use backoff::BackoffStore;
use gcra::{CoreClock, Gcra};

/// The rate-limiting port used by the web layer.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Consumes one request for `key` in `class` (GCRA request rate).
    async fn check(&self, class: RouteClass, key: &LimitKey) -> Decision;

    /// The remaining progressive-backoff lock window of `key`, if it is locked.
    async fn backoff(&self, key: &LimitKey) -> Option<Duration>;

    /// Records a failed attempt for `key` and returns its new backoff state.
    async fn record_failure(&self, key: &LimitKey) -> Backoff;

    /// Records a successful attempt: forgets all failures of `key`.
    async fn record_success(&self, key: &LimitKey);

    /// The brute-force decision for an attempt keyed `strict` (identifier + IP) and `loose`
    /// (identifier only). A locked strict key denies; a loose key over the hourly threshold
    /// requires a CAPTCHA when one is available, otherwise a short delay.
    async fn brute_force_gate(
        &self,
        strict: &LimitKey,
        loose: &LimitKey,
        captcha_available: bool,
    ) -> Decision;
}

/// In-process [`RateLimiter`]: governor GCRA per route class plus a moka backoff store.
pub struct InProcessLimiter {
    config: LimiterConfig,
    gcra: Gcra,
    backoff: BackoffStore,
}

impl InProcessLimiter {
    /// A limiter with `config`, driven by `clock`.
    pub fn new(config: LimiterConfig, clock: Arc<dyn Clock>) -> Self {
        let gcra = Gcra::new(&config, CoreClock::new(clock.clone()));
        let backoff = BackoffStore::new(&config, clock);
        Self {
            config,
            gcra,
            backoff,
        }
    }

    /// The configuration in effect.
    pub fn config(&self) -> &LimiterConfig {
        &self.config
    }

    /// Number of keys currently tracked by the GCRA state of `class` (for metrics).
    pub fn tracked_keys(&self, class: RouteClass) -> usize {
        self.gcra.tracked_keys(class)
    }
}

#[async_trait]
impl RateLimiter for InProcessLimiter {
    async fn check(&self, class: RouteClass, key: &LimitKey) -> Decision {
        if !self.config.enabled {
            return Decision::Allow;
        }
        if self.gcra.housekeeping() {
            self.backoff.housekeeping();
        }
        self.gcra.check(class, key)
    }

    async fn backoff(&self, key: &LimitKey) -> Option<Duration> {
        if !self.config.enabled {
            return None;
        }
        self.backoff.backoff(key)
    }

    async fn record_failure(&self, key: &LimitKey) -> Backoff {
        if !self.config.enabled {
            return Backoff {
                failures: 0,
                locked_for: None,
            };
        }
        self.backoff.record_failure(key)
    }

    async fn record_success(&self, key: &LimitKey) {
        if self.config.enabled {
            self.backoff.record_success(key);
        }
    }

    async fn brute_force_gate(
        &self,
        strict: &LimitKey,
        loose: &LimitKey,
        captcha_available: bool,
    ) -> Decision {
        if !self.config.enabled {
            return Decision::Allow;
        }
        self.backoff
            .brute_force_gate(strict, loose, captcha_available)
    }
}
