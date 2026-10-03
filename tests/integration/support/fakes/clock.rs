//! A `Clock` the test sets.

use std::sync::atomic::{AtomicU64, Ordering};

use mcpjump::sys::clock::Clock;

/// A clock that reads whatever the test last set.
#[derive(Debug)]
pub(crate) struct FixedClock(AtomicU64);

/// The time fake clocks start at: 2030-01-01T00:00:00Z.
pub(crate) const START: u64 = 1_893_456_000;

impl FixedClock {
    /// Sets the time.
    pub(crate) fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Default for FixedClock {
    fn default() -> Self {
        Self(AtomicU64::new(START))
    }
}

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
