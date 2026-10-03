//! The OS keyring store for this platform: a thin adapter, one arm per OS,
//! each covered on its own runner.

use std::sync::Arc;

use keyring_core::CredentialStore;

use crate::store::MAX_RECORD_BYTES;

/// Largest value one keyring entry holds. Windows Credential Manager caps a
/// blob at 2560 bytes; the other keyrings take a whole record.
pub const MAX_ENTRY_BYTES: usize = if cfg!(windows) {
    2560
} else {
    MAX_RECORD_BYTES
};

/// Starts the macOS login keychain store.
///
/// # Errors
/// The store's error if it cannot start.
#[cfg(target_os = "macos")]
pub fn start() -> keyring_core::Result<Arc<CredentialStore>> {
    apple_native_keyring_store::keychain::Store::new()
        .map(|store| -> Arc<CredentialStore> { store })
}

/// Starts the Windows Credential Manager store.
///
/// # Errors
/// The store's error if it cannot start.
#[cfg(windows)]
pub fn start() -> keyring_core::Result<Arc<CredentialStore>> {
    windows_native_keyring_store::Store::new().map(|store| -> Arc<CredentialStore> { store })
}

/// Starts the Secret Service store over D-Bus.
///
/// # Errors
/// The store's error if it cannot start, such as no session bus.
#[cfg(target_os = "linux")]
pub fn start() -> keyring_core::Result<Arc<CredentialStore>> {
    zbus_secret_service_keyring_store::Store::new().map(|store| -> Arc<CredentialStore> { store })
}

/// No OS keyring is supported here.
///
/// # Errors
/// Always `NotSupportedByStore`.
#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
pub fn start() -> keyring_core::Result<Arc<CredentialStore>> {
    Err(keyring_core::Error::NotSupportedByStore(
        "no OS keyring is supported on this platform".to_owned(),
    ))
}
