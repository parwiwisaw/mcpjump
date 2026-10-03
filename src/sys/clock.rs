//! The wall clock, for token expiry.

use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};

/// Tells the time.
pub trait Clock: Debug + Sync {
    /// Seconds since the Unix epoch.
    fn now_unix(&self) -> u64;
}

/// The system clock. Constructed only in `main.rs`.
#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    /// A clock set before 1970 reads as 0, so every token looks expired.
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    }
}
