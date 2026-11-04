//! Time for timeouts and time limits, on every target.
//!
//! `std::time::Instant::now()` panics on wasm32-unknown-unknown, which has no clock of its
//! own, so the library reads the time from here. [`Instant`] is `std::time::Instant` on
//! native targets and, through the `web-time` crate, the JavaScript clock
//! (`performance.now()`) on the web. A search that runs on the caller's thread is given a
//! [`Deadline`] instead of having a timer thread stop it.

use std::time::Duration;

pub(crate) use web_time::Instant;

/// When a search has to stop.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadline(Option<Instant>);

impl Deadline {
    /// A deadline that never passes, for a search something else stops (on native
    /// targets, the timer thread). Checking it doesn't read the clock.
    #[cfg_attr(target_family = "wasm", allow(dead_code))]
    pub(crate) const NEVER: Deadline = Deadline(None);

    /// The deadline `timeout` from now.
    #[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
    pub(crate) fn after(timeout: Duration) -> Deadline {
        // Too far away to represent: never
        Deadline(Instant::now().checked_add(timeout))
    }

    /// Whether the deadline has passed.
    pub(crate) fn has_passed(&self) -> bool {
        self.0.is_some_and(|deadline| Instant::now() >= deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadlines_pass_when_due() {
        assert!(!Deadline::NEVER.has_passed());
        assert!(Deadline::after(Duration::ZERO).has_passed());
        assert!(!Deadline::after(Duration::from_secs(3600)).has_passed());
        // u32::MAX seconds, the longest `--cracking-timeout`
        assert!(!Deadline::after(Duration::from_secs(u64::from(u32::MAX))).has_passed());
        // Past what an Instant can hold
        assert!(!Deadline::after(Duration::MAX).has_passed());
    }
}
