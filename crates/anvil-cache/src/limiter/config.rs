//! Limiter configuration and its defaults.

use std::num::NonZeroU32;
use std::time::Duration;

/// A GCRA quota: `burst` requests at once, refilled at one request per `period / count`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateQuota {
    /// Requests allowed per `period` (sustained rate).
    pub count: NonZeroU32,
    /// The period `count` refers to.
    pub period: Duration,
    /// Requests allowed back to back.
    pub burst: NonZeroU32,
}

impl RateQuota {
    /// `count` requests per second with the given burst. Zero values are clamped to 1.
    pub fn per_second(count: u32, burst: u32) -> Self {
        Self::new(count, Duration::from_secs(1), burst)
    }

    /// `count` requests per minute with the given burst. Zero values are clamped to 1.
    pub fn per_minute(count: u32, burst: u32) -> Self {
        Self::new(count, Duration::from_secs(60), burst)
    }

    /// `count` requests per `period` with the given burst. Zero values are clamped to 1, and a
    /// zero period is treated as one nanosecond.
    pub fn new(count: u32, period: Duration, burst: u32) -> Self {
        Self {
            count: NonZeroU32::new(count).unwrap_or(NonZeroU32::MIN),
            period: period.max(Duration::from_nanos(1)),
            burst: NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN),
        }
    }

    /// The interval after which one request's worth of quota is replenished.
    pub fn replenish_interval(&self) -> Duration {
        (self.period / self.count.get()).max(Duration::from_nanos(1))
    }

    pub(crate) fn to_governor(self) -> governor::Quota {
        governor::Quota::with_period(self.replenish_interval())
            .unwrap_or_else(|| governor::Quota::per_second(NonZeroU32::MAX))
            .allow_burst(self.burst)
    }
}

/// Limiter configuration (ARCHITECTURE §11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimiterConfig {
    /// Operator switch. `false` turns the limiter off entirely: every check allows and no
    /// failures are recorded. Default `true`.
    pub enabled: bool,
    /// [`super::RouteClass::Auth`] quota (per key, normally per IP).
    pub auth: RateQuota,
    /// [`super::RouteClass::Token`] quota for every key except [`super::LimitKey::Client`].
    pub token: RateQuota,
    /// [`super::RouteClass::Token`] quota for [`super::LimitKey::Client`] keys.
    pub token_client: RateQuota,
    /// [`super::RouteClass::Admin`] quota.
    pub admin: RateQuota,
    /// [`super::RouteClass::Default`] quota.
    pub default: RateQuota,
    /// Failures allowed before progressive backoff starts.
    pub free_attempts: u32,
    /// The first lock duration; doubled for every further failure.
    pub base: Duration,
    /// The longest lock. Entries are forgotten after `2 * cap` without failures.
    pub cap: Duration,
    /// Failures per hour on an identifier-only key before CAPTCHA (or a delay) is required.
    pub loose_threshold_per_hour: u32,
    /// Upper bound on keys tracked for progressive backoff.
    pub max_tracked_keys: u64,
}

impl Default for LimiterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auth: RateQuota::per_minute(10, 5),
            token: RateQuota::per_second(50, 50),
            token_client: RateQuota::per_second(100, 100),
            admin: RateQuota::per_second(20, 20),
            default: RateQuota::per_second(50, 50),
            free_attempts: 5,
            base: Duration::from_secs(1),
            cap: Duration::from_secs(15 * 60),
            loose_threshold_per_hour: 50,
            max_tracked_keys: 100_000,
        }
    }
}
