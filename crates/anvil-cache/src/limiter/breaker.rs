//! Circuit breaker in front of the shared (Redis) limiter backend.
//!
//! After a backend error the breaker opens for a cool-down: calls skip Redis entirely instead of
//! each waiting out the response timeout. Once the cool-down has passed, exactly one call probes
//! Redis (half-open); its success closes the breaker, its failure re-opens it. A probe that never
//! reports back (its future was dropped) is replaced after another cool-down, so the breaker
//! cannot get stuck half-open.
//!
//! Time comes from the injected core clock, like every other limiter decision.

use std::sync::Mutex;
use std::time::Duration;

use time::OffsetDateTime;

/// How long the breaker stays open after a backend error.
pub const BREAKER_COOL_DOWN: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Closed,
    Open { until: OffsetDateTime },
    HalfOpen { since: OffsetDateTime },
}

/// Whether a call may use the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Permit {
    /// Use the backend.
    Proceed,
    /// Skip the backend; the breaker is open (or another call is probing).
    Skip,
}

/// A state change worth reporting (metrics, logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transition {
    /// The backend failed while the breaker was closed (healthy -> degraded).
    Opened,
    /// A probe succeeded (degraded -> healthy).
    Closed,
}

pub(crate) struct Breaker {
    cool_down: Duration,
    state: Mutex<State>,
}

impl Breaker {
    pub(crate) fn new(cool_down: Duration) -> Self {
        Self {
            cool_down,
            state: Mutex::new(State::Closed),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // The state is a plain value; a poisoned lock still holds a valid one.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Asks to use the backend at `now`.
    pub(crate) fn permit(&self, now: OffsetDateTime) -> Permit {
        let mut state = self.lock();
        match *state {
            State::Closed => Permit::Proceed,
            State::Open { until } if now >= until => {
                *state = State::HalfOpen { since: now };
                Permit::Proceed
            }
            State::HalfOpen { since } if now - since >= self.cool_down => {
                *state = State::HalfOpen { since: now };
                Permit::Proceed
            }
            State::Open { .. } | State::HalfOpen { .. } => Permit::Skip,
        }
    }

    /// Records a successful backend call.
    pub(crate) fn success(&self) -> Option<Transition> {
        let mut state = self.lock();
        let was_closed = *state == State::Closed;
        *state = State::Closed;
        (!was_closed).then_some(Transition::Closed)
    }

    /// Records a failed backend call at `now`.
    pub(crate) fn failure(&self, now: OffsetDateTime) -> Option<Transition> {
        let mut state = self.lock();
        let was_closed = *state == State::Closed;
        *state = State::Open {
            until: now + self.cool_down,
        };
        was_closed.then_some(Transition::Opened)
    }

    /// How long a fail-closed caller should wait: the rest of the open window, or a full
    /// cool-down when the breaker is not open (a failure just happened, or a probe is running).
    pub(crate) fn retry_after(&self, now: OffsetDateTime) -> Duration {
        match *self.lock() {
            State::Open { until } if until > now => (until - now).unsigned_abs(),
            _ => self.cool_down,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    #[test]
    fn closed_breaker_proceeds() {
        let b = Breaker::new(BREAKER_COOL_DOWN);
        assert_eq!(b.permit(t0()), Permit::Proceed);
        assert_eq!(b.success(), None);
        assert_eq!(b.retry_after(t0()), BREAKER_COOL_DOWN);
    }

    #[test]
    fn failure_opens_for_the_cool_down_then_one_probe() {
        let b = Breaker::new(Duration::from_secs(5));
        assert_eq!(b.failure(t0()), Some(Transition::Opened));
        assert_eq!(b.permit(t0() + Duration::from_secs(1)), Permit::Skip);
        assert_eq!(
            b.retry_after(t0() + Duration::from_secs(1)),
            Duration::from_secs(4)
        );
        // After the cool-down exactly one probe proceeds.
        let later = t0() + Duration::from_secs(5);
        assert_eq!(b.permit(later), Permit::Proceed);
        assert_eq!(b.permit(later), Permit::Skip);
        assert_eq!(b.success(), Some(Transition::Closed));
        assert_eq!(b.permit(later), Permit::Proceed);
    }

    #[test]
    fn failed_probe_reopens_without_a_new_transition() {
        let b = Breaker::new(Duration::from_secs(5));
        b.failure(t0());
        let later = t0() + Duration::from_secs(5);
        assert_eq!(b.permit(later), Permit::Proceed);
        assert_eq!(b.failure(later), None);
        assert_eq!(b.permit(later + Duration::from_secs(4)), Permit::Skip);
        assert_eq!(b.permit(later + Duration::from_secs(5)), Permit::Proceed);
    }

    #[test]
    fn abandoned_probe_is_replaced_after_a_cool_down() {
        let b = Breaker::new(Duration::from_secs(5));
        b.failure(t0());
        let probe = t0() + Duration::from_secs(5);
        assert_eq!(b.permit(probe), Permit::Proceed);
        // The probe never reports back.
        assert_eq!(b.permit(probe + Duration::from_secs(4)), Permit::Skip);
        assert_eq!(b.permit(probe + Duration::from_secs(5)), Permit::Proceed);
    }
}
