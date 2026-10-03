//! The per-server credential lock. It is held for every credential change,
//! so a logout or remove cannot race a refresh that would bring deleted
//! tokens back. Lock order is always `config.lock`, then this one.

use std::io;
use std::path::Path;
use std::time::Duration;

use crate::config::validate::ServerName;
use crate::error::{Error, ErrorKind};
use crate::files::{self, FileLock};

/// Runs `work` under the server lock. A keyring call abandoned on timeout
/// may still write, so after `keyring_timeout` the lock is kept until the
/// process exits: no other process can change these credentials under it.
///
/// # Errors
/// Those of [`server_lock`], then whatever `work` returns.
pub fn with_server_lock(
    config_dir: &Path,
    server: &ServerName,
    wait: Duration,
    work: &dyn Fn() -> Result<(), Error>,
) -> Result<(), Error> {
    let lock = server_lock(config_dir, server, wait)?;
    let result = work();
    release(lock, &result);
    result
}

/// Releases a server lock once its work has `result`. A keyring call
/// abandoned on timeout may still write, so after `keyring_timeout` the
/// lock is kept until the process exits.
pub fn release<T>(lock: FileLock, result: &Result<T, Error>) {
    if result
        .as_ref()
        .is_err_and(|error| error.kind() == ErrorKind::KeyringTimeout)
    {
        std::mem::forget(lock);
    }
}

/// Takes `<config_dir>/locks/servers/<server>.lock`, waiting at most `wait`.
/// The subdirectory keeps a server named `config` off the config lock.
///
/// # Errors
/// `credential_lock_timeout` if another process holds it for longer, or
/// `credential_store` if the lock file cannot be created or locked.
pub fn server_lock(
    config_dir: &Path,
    server: &ServerName,
    wait: Duration,
) -> Result<FileLock, Error> {
    let path = config_dir
        .join("locks")
        .join("servers")
        .join(format!("{}.lock", server.as_str()));
    files::lock(&path, wait).map_err(|error| {
        if error.kind() == io::ErrorKind::TimedOut {
            Error::new(
                ErrorKind::CredentialLockTimeout,
                format!(
                    "another mcpjump process is changing the credentials for {:?}; try again",
                    server.as_str()
                ),
            )
        } else {
            Error::new(
                ErrorKind::CredentialStore,
                format!("{}: {error}", path.display()),
            )
        }
    })
}
