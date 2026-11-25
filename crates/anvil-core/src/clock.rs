//! The clock port. Core code never calls `OffsetDateTime::now_utc()` directly; it asks a
//! [`Clock`], so tests can control time.

use time::OffsetDateTime;

use crate::model::truncate_to_ms;

/// Source of the current time.
pub trait Clock: Send + Sync {
    /// The current UTC time, truncated to whole milliseconds (the storage precision).
    fn now(&self) -> OffsetDateTime;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        truncate_to_ms(OffsetDateTime::now_utc())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_ms_truncated_utc() {
        let now = SystemClock.now();
        assert_eq!(now, truncate_to_ms(now));
        assert!(now.offset().is_utc());
    }
}
