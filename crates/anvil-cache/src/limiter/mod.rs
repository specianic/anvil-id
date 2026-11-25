//! The one rate limiter of the codebase (ARCHITECTURE §11).
//!
//! - Request rate: GCRA per [`RouteClass`] via `governor`, keyed by [`LimitKey`].
//!
//! Time always comes from the injected `anvil_core` clock and nothing here sleeps: callers
//! receive a `retry_after` and decide how to respond.

mod config;
mod gcra;
mod types;

use std::sync::Arc;

use anvil_core::ports::Clock;
use async_trait::async_trait;

pub use config::{LimiterConfig, RateQuota};
pub use types::{Backoff, Decision, LimitKey, RouteClass};

use gcra::{CoreClock, Gcra};

/// The rate-limiting port used by the web layer.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Consumes one request for `key` in `class` (GCRA request rate).
    async fn check(&self, class: RouteClass, key: &LimitKey) -> Decision;
}

/// In-process [`RateLimiter`]: governor GCRA per route class.
pub struct InProcessLimiter {
    config: LimiterConfig,
    gcra: Gcra,
}

impl InProcessLimiter {
    /// A limiter with `config`, driven by `clock`.
    pub fn new(config: LimiterConfig, clock: Arc<dyn Clock>) -> Self {
        let gcra = Gcra::new(&config, CoreClock::new(clock));
        Self { config, gcra }
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
        self.gcra.check(class, key)
    }
}
