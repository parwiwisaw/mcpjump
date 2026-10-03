//! Credential storage. A record is JSON text stored under a key: a server
//! and the kind of record. The OS keyring is preferred; a private file is the
//! fallback. `select` decides which one a server uses.

pub mod chunk;
pub mod file;
pub mod keyring;
pub mod lock;
pub mod platform;
pub mod record;
pub mod select;
pub mod system;

use std::fmt;

use crate::config::validate::ServerName;
use crate::error::{Error, ErrorKind};

/// The keyring service every entry is stored under.
pub const SERVICE: &str = "mcpjump";

/// Largest record any backend accepts: what fits in the most keyring chunks.
pub const MAX_RECORD_BYTES: usize = chunk::CHUNK_BYTES * chunk::MAX_CHUNKS;

/// The kinds of record kept per server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// Access and refresh tokens.
    Tokens,
    /// The OAuth client registration.
    Registration,
}

impl RecordKind {
    /// Every kind, for deleting all of a server's credentials.
    pub const ALL: [Self; 2] = [Self::Tokens, Self::Registration];

    /// The spelling used in keyring accounts and file names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tokens => "tokens",
            Self::Registration => "registration",
        }
    }
}

/// Where one record is stored: a server and a record kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    server: ServerName,
    kind: RecordKind,
}

impl Key {
    /// The key for `kind` of `server`.
    #[must_use]
    pub const fn new(server: ServerName, kind: RecordKind) -> Self {
        Self { server, kind }
    }

    /// The server.
    #[must_use]
    pub const fn server(&self) -> &ServerName {
        &self.server
    }

    /// The record kind.
    #[must_use]
    pub const fn kind(&self) -> RecordKind {
        self.kind
    }

    /// The keyring account: `<server>/<kind>`.
    #[must_use]
    pub fn account(&self) -> String {
        format!("{}/{}", self.server.as_str(), self.kind.as_str())
    }
}

/// A place to keep credential records. Implementations must be safe to call
/// from several processes, given the caller holds the server's lock.
pub trait CredentialStore: fmt::Debug {
    /// The record under `key`, or `None` if nothing is stored.
    ///
    /// # Errors
    /// `credential_store`, `credential_invalid`, `credential_too_large` or
    /// `keyring_timeout`. A store that cannot be read is never "no record".
    fn get(&self, key: &Key) -> Result<Option<Vec<u8>>, Error>;

    /// Stores `record` under `key`, replacing any earlier record. A failure
    /// leaves the earlier record readable.
    ///
    /// # Errors
    /// `credential_invalid` if [`check_record`] rejects it, otherwise as
    /// for [`CredentialStore::get`].
    fn set(&self, key: &Key, record: &[u8]) -> Result<(), Error>;

    /// Deletes the record under `key`. Deleting nothing succeeds.
    ///
    /// # Errors
    /// As for [`CredentialStore::get`].
    fn delete(&self, key: &Key) -> Result<(), Error>;
}

/// Checks a record before any store writes it: JSON object text of at most
/// [`MAX_RECORD_BYTES`].
///
/// # Errors
/// `credential_too_large` or `credential_invalid`.
pub fn check_record(key: &Key, record: &[u8]) -> Result<(), Error> {
    if record.len() > MAX_RECORD_BYTES {
        return Err(too_large(key));
    }
    if record.first() != Some(&b'{') {
        return Err(Error::new(
            ErrorKind::CredentialInvalid,
            format!(
                "{}: a credential record must be a JSON object",
                describe(key)
            ),
        ));
    }
    Ok(())
}

/// The error for a record over [`MAX_RECORD_BYTES`].
#[must_use]
pub fn too_large(key: &Key) -> Error {
    Error::new(
        ErrorKind::CredentialTooLarge,
        format!("{} is larger than {MAX_RECORD_BYTES} bytes", describe(key)),
    )
}

/// The error for a stored record that is damaged or fails validation.
#[must_use]
pub fn corrupt(key: &Key) -> Error {
    Error::new(
        ErrorKind::CredentialInvalid,
        format!(
            "{} is damaged; run `mcpjump logout {name}` and `mcpjump login {name}`",
            describe(key),
            name = key.server().as_str()
        ),
    )
}

/// `the stored tokens for "name"`, for messages.
fn describe(key: &Key) -> String {
    format!(
        "the stored {} for {:?}",
        key.kind().as_str(),
        key.server().as_str()
    )
}
