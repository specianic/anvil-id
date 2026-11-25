//! Progressive backoff and the two-tier brute-force gate, stored in a bounded `moka` cache.
//!
//! All time decisions use the injected core clock, so behaviour is deterministic under a fake
//! clock. The moka time-to-idle (real time) and capacity bound memory; the clock-based idle
//! check below gives the exact `2 * cap` expiry semantics independently of moka's timer.

use std::sync::Arc;
use std::time::Duration;

use anvil_core::ports::Clock;
use moka::sync::Cache;
use time::OffsetDateTime;

use super::config::LimiterConfig;
use super::types::{Backoff, Decision, LimitKey};

/// Length of the loose-tier counting window.
const LOOSE_WINDOW: Duration = Duration::from_secs(3_600);

#[derive(Debug, Clone, Copy)]
struct Entry {
    /// Consecutive failures (strict keys) or failures in the current window (loose keys).
    failures: u32,
    locked_until: Option<OffsetDateTime>,
    last_failure: OffsetDateTime,
    loose_window_start: OffsetDateTime,
    loose_count: u32,
}

pub(crate) struct BackoffStore {
    clock: Arc<dyn Clock>,
    free_attempts: u32,
    base: Duration,
    cap: Duration,
    idle: Duration,
    loose_threshold: u32,
    cache: Cache<LimitKey, Entry>,
}

impl BackoffStore {
    pub(crate) fn new(config: &LimiterConfig, clock: Arc<dyn Clock>) -> Self {
        let idle = config.cap.saturating_mul(2).max(Duration::from_secs(1));
        let cache = Cache::builder()
            .max_capacity(config.max_tracked_keys)
            .time_to_idle(idle)
            .build();
        Self {
            clock,
            free_attempts: config.free_attempts,
            base: config.base,
            cap: config.cap,
            idle,
            loose_threshold: config.loose_threshold_per_hour.max(1),
            cache,
        }
    }

    fn is_stale(&self, entry: &Entry, now: OffsetDateTime) -> bool {
        now - entry.last_failure >= self.idle
    }

    /// The live entry for `key`, dropping it if it has been idle for `2 * cap`.
    fn live(&self, key: &LimitKey, now: OffsetDateTime) -> Option<Entry> {
        let entry = self.cache.get(key)?;
        if self.is_stale(&entry, now) {
            self.cache.invalidate(key);
            return None;
        }
        Some(entry)
    }

    /// `base * 2^(failures - free - 1)` capped at `cap`, once failures exceed the free attempts.
    fn lock_duration(&self, failures: u32) -> Option<Duration> {
        let over = failures.checked_sub(self.free_attempts)?.checked_sub(1)?;
        let factor = 1u32.checked_shl(over).unwrap_or(u32::MAX);
        Some(self.base.saturating_mul(factor).min(self.cap))
    }

    fn remaining(locked_until: Option<OffsetDateTime>, now: OffsetDateTime) -> Option<Duration> {
        let until = locked_until?;
        let left = until - now;
        if left.is_positive() {
            Some(left.unsigned_abs())
        } else {
            None
        }
    }

    pub(crate) fn backoff(&self, key: &LimitKey) -> Option<Duration> {
        let now = self.clock.now();
        Self::remaining(self.live(key, now)?.locked_until, now)
    }

    pub(crate) fn record_failure(&self, key: &LimitKey) -> Backoff {
        let now = self.clock.now();
        let loose = key.is_loose_tier();
        let updated = self
            .cache
            .entry(key.clone())
            .and_upsert_with(|existing| {
                let previous = existing
                    .map(moka::Entry::into_value)
                    .filter(|e| !self.is_stale(e, now));
                let mut e = previous.unwrap_or(Entry {
                    failures: 0,
                    locked_until: None,
                    last_failure: now,
                    loose_window_start: now,
                    loose_count: 0,
                });
                if now - e.loose_window_start >= LOOSE_WINDOW {
                    e.loose_window_start = now;
                    e.loose_count = 0;
                }
                e.loose_count = e.loose_count.saturating_add(1);
                e.last_failure = now;
                if loose {
                    // The loose tier is never locked: it only escalates to CAPTCHA or a delay.
                    e.failures = e.loose_count;
                } else {
                    e.failures = e.failures.saturating_add(1);
                    e.locked_until = self.lock_duration(e.failures).map(|d| now + d);
                }
                e
            })
            .into_value();
        Backoff {
            failures: updated.failures,
            locked_for: Self::remaining(updated.locked_until, now),
        }
    }

    pub(crate) fn record_success(&self, key: &LimitKey) {
        self.cache.invalidate(key);
    }

    fn loose_over_threshold(&self, key: &LimitKey, now: OffsetDateTime) -> bool {
        self.live(key, now).is_some_and(|e| {
            now - e.loose_window_start < LOOSE_WINDOW && e.loose_count >= self.loose_threshold
        })
    }

    pub(crate) fn brute_force_gate(
        &self,
        strict: &LimitKey,
        loose: &LimitKey,
        captcha_available: bool,
    ) -> Decision {
        let now = self.clock.now();
        if let Some(retry_after) = self
            .live(strict, now)
            .and_then(|e| Self::remaining(e.locked_until, now))
        {
            return Decision::Deny { retry_after };
        }
        if self.loose_over_threshold(loose, now) {
            if captcha_available {
                return Decision::RequireCaptcha;
            }
            let delay = self
                .base
                .saturating_mul(2)
                .min(self.cap)
                .max(Duration::from_millis(1));
            return Decision::Deny { retry_after: delay };
        }
        Decision::Allow
    }

    /// Runs moka's pending maintenance (expiry, eviction).
    pub(crate) fn housekeeping(&self) {
        self.cache.run_pending_tasks();
    }
}
