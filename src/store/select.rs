//! Which backend holds a server's credentials. The backend recorded at
//! login always wins, so one server's credentials are never split across
//! two backends. Otherwise the `credential_store` setting decides, and
//! `auto` falls back to the file only when the keyring cannot start.

use std::fmt;
use std::path::Path;

use crate::config::limits::Limits;
use crate::config::model::{Backend, CredentialStoreKind};
use crate::config::validate::ServerName;
use crate::error::{Error, ErrorKind};
use crate::store::CredentialStore;

/// The result of starting the OS keyring.
#[derive(Debug)]
pub enum KeyringStart {
    /// The keyring is ready.
    Ready(Box<dyn CredentialStore>),
    /// No keyring exists here, for this reason.
    Unavailable(String),
}

/// Opens the credential backends. The seam that lets tests choose what the
/// keyring does.
pub trait StoreOpener: fmt::Debug {
    /// Starts the OS keyring.
    ///
    /// # Errors
    /// `credential_store` for a keyring that refuses access,
    /// `keyring_timeout` if it does not start in time.
    fn keyring(&self, limits: &Limits) -> Result<KeyringStart, Error>;

    /// The file store under `config_dir`.
    fn file(&self, config_dir: &Path) -> Box<dyn CredentialStore>;
}

/// What selection needs to know about one server.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The server.
    pub server: &'a ServerName,
    /// The backend recorded at the server's last login.
    pub recorded: Option<Backend>,
    /// The `credential_store` setting.
    pub policy: CredentialStoreKind,
    /// The config directory, which holds the credential files.
    pub config_dir: &'a Path,
    /// The config file, named in the fallback notice.
    pub config_file: &'a Path,
    /// The limits, for the keyring timeout.
    pub limits: &'a Limits,
}

/// The backend chosen for a server.
#[derive(Debug)]
pub struct Selected {
    /// The store to use.
    pub store: Box<dyn CredentialStore>,
    /// Which backend it is, to record at login.
    pub backend: Backend,
    /// A notice for stderr when the credentials are in a file.
    pub warning: Option<String>,
}

/// Chooses the backend for `request`.
///
/// # Errors
/// `credential_store` when the keyring is required but unavailable or
/// refuses access, `keyring_timeout`.
pub fn select(opener: &dyn StoreOpener, request: &Request<'_>) -> Result<Selected, Error> {
    match (request.recorded, request.policy) {
        (Some(Backend::Keyring), _) | (None, CredentialStoreKind::Keyring) => {
            keyring_only(opener, request)
        }
        (Some(Backend::File), policy) => {
            let warning = (policy != CredentialStoreKind::File).then(|| reminder(request));
            Ok(file(opener, request, warning))
        }
        (None, CredentialStoreKind::File) => Ok(file(opener, request, None)),
        (None, CredentialStoreKind::Auto) => match opener.keyring(request.limits)? {
            KeyringStart::Ready(store) => Ok(keyring(store)),
            KeyringStart::Unavailable(reason) => {
                let notice = fallback_notice(request, &reason);
                Ok(file(opener, request, Some(notice)))
            }
        },
    }
}

fn keyring_only(opener: &dyn StoreOpener, request: &Request<'_>) -> Result<Selected, Error> {
    match opener.keyring(request.limits)? {
        KeyringStart::Ready(store) => Ok(keyring(store)),
        KeyringStart::Unavailable(reason) => Err(Error::new(
            ErrorKind::CredentialStore,
            format!(
                "the OS keyring is not available ({reason}); start one, or set credential_store = \"file\" in {}",
                request.config_file.display()
            ),
        )),
    }
}

fn keyring(store: Box<dyn CredentialStore>) -> Selected {
    Selected {
        store,
        backend: Backend::Keyring,
        warning: None,
    }
}

fn file(opener: &dyn StoreOpener, request: &Request<'_>, warning: Option<String>) -> Selected {
    Selected {
        store: opener.file(request.config_dir),
        backend: Backend::File,
        warning,
    }
}

/// The one-line warning on every use of file credentials the user has not
/// chosen.
fn reminder(request: &Request<'_>) -> String {
    format!(
        "credentials for {:?} are stored unencrypted in {}",
        request.server.as_str(),
        credentials_dir(request).display()
    )
}

/// The notice on the first fallback to the file.
fn fallback_notice(request: &Request<'_>, reason: &str) -> String {
    let server = request.server.as_str();
    format!(
        "no OS keyring is available ({reason}).\n\
         Credentials for {server:?} will be stored UNENCRYPTED in {dir}.\n\
         To use a keyring, start one (on Linux, a Secret Service such as gnome-keyring), \
         then run `mcpjump logout {server}` and `mcpjump login {server}`.\n\
         To accept file storage and silence this notice, set credential_store = \"file\" in {config}.",
        dir = credentials_dir(request).display(),
        config = request.config_file.display(),
    )
}

fn credentials_dir(request: &Request<'_>) -> std::path::PathBuf {
    request.config_dir.join("credentials")
}
