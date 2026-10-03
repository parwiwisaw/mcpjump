//! `[limits]`: defaults and validated ranges.

use std::time::Duration;

use serde::Deserialize;

use crate::error::{Error, ErrorKind};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

/// Time, size and count limits. Every field is range-checked by [`Limits::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub auth_network_budget_secs: u64,
    pub tool_timeout_secs: u64,
    pub stream_idle_secs: u64,
    pub login_timeout_secs: u64,
    pub validation_timeout_secs: u64,
    pub stdin_timeout_secs: u64,
    pub browser_timeout_secs: u64,
    pub keyring_timeout_secs: u64,
    pub lock_wait_secs: u64,
    pub max_response_bytes: u64,
    pub max_metadata_bytes: u64,
    pub max_params_bytes: u64,
    pub max_json_depth: u64,
    pub max_tool_pages: u64,
    pub max_tools: u64,
    pub max_tools_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 5,
            request_timeout_secs: 15,
            auth_network_budget_secs: 60,
            tool_timeout_secs: 120,
            stream_idle_secs: 30,
            login_timeout_secs: 300,
            validation_timeout_secs: 2,
            stdin_timeout_secs: 30,
            browser_timeout_secs: 5,
            keyring_timeout_secs: 3,
            lock_wait_secs: 20,
            max_response_bytes: 16 * MIB,
            max_metadata_bytes: MIB,
            max_params_bytes: MIB,
            max_json_depth: 64,
            max_tool_pages: 100,
            max_tools: 1000,
            max_tools_bytes: 16 * MIB,
        }
    }
}

impl Limits {
    /// How long to wait for a config or credential lock.
    #[must_use]
    pub const fn lock_wait(&self) -> Duration {
        Duration::from_secs(self.lock_wait_secs)
    }

    /// How long one OS keyring call may take.
    #[must_use]
    pub const fn keyring_timeout(&self) -> Duration {
        Duration::from_secs(self.keyring_timeout_secs)
    }

    /// Each limit's config key, value and inclusive range.
    fn ranges(&self) -> [(&'static str, u64, u64, u64); 18] {
        [
            ("connect_timeout_secs", self.connect_timeout_secs, 1, 60),
            ("request_timeout_secs", self.request_timeout_secs, 1, 300),
            (
                "auth_network_budget_secs",
                self.auth_network_budget_secs,
                1,
                600,
            ),
            ("tool_timeout_secs", self.tool_timeout_secs, 1, 3600),
            ("stream_idle_secs", self.stream_idle_secs, 1, 600),
            ("login_timeout_secs", self.login_timeout_secs, 30, 1800),
            (
                "validation_timeout_secs",
                self.validation_timeout_secs,
                1,
                30,
            ),
            ("stdin_timeout_secs", self.stdin_timeout_secs, 1, 600),
            ("browser_timeout_secs", self.browser_timeout_secs, 1, 30),
            ("keyring_timeout_secs", self.keyring_timeout_secs, 1, 60),
            ("lock_wait_secs", self.lock_wait_secs, 1, 600),
            (
                "max_response_bytes",
                self.max_response_bytes,
                KIB,
                256 * MIB,
            ),
            ("max_metadata_bytes", self.max_metadata_bytes, KIB, 16 * MIB),
            ("max_params_bytes", self.max_params_bytes, KIB, 64 * MIB),
            ("max_json_depth", self.max_json_depth, 8, 256),
            ("max_tool_pages", self.max_tool_pages, 1, 10_000),
            ("max_tools", self.max_tools, 1, 100_000),
            ("max_tools_bytes", self.max_tools_bytes, KIB, 256 * MIB),
        ]
    }

    /// Checks every limit against its range, and that a lock wait can outlast
    /// one request made by the process holding the lock.
    ///
    /// # Errors
    /// `config_invalid` naming the first key out of range.
    pub fn validate(&self) -> Result<(), Error> {
        for (key, value, min, max) in self.ranges() {
            if !(min..=max).contains(&value) {
                return Err(Error::new(
                    ErrorKind::ConfigInvalid,
                    format!("limits.{key}: {value} is outside {min}..={max}"),
                ));
            }
        }
        if self.lock_wait_secs <= self.request_timeout_secs {
            return Err(Error::new(
                ErrorKind::ConfigInvalid,
                "limits.lock_wait_secs: must be greater than limits.request_timeout_secs",
            ));
        }
        Ok(())
    }
}
