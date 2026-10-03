//! The OS keyring through `keyring-core`. Every call runs on its own thread
//! and is abandoned after the timeout, so a hung keyring can never hang the
//! CLI. Records larger than one entry are chunked; see [`chunk`].

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::error::{Error, ErrorKind};
use crate::store::chunk::{self, CHUNK_BYTES, Head, MAX_CHUNKS, Manifest, Slot};
use crate::store::select::KeyringStart;
use crate::store::{self, CredentialStore, Key, MAX_RECORD_BYTES, SERVICE};
use crate::sys::deadline::{self, Limit, Wait, clipped_wait};
use crate::sys::worker;

/// A started `keyring-core` store.
pub type PlatformStore = Arc<keyring_core::CredentialStore>;

/// Starts a `keyring-core` store.
pub type StartFn = fn() -> keyring_core::Result<PlatformStore>;

/// An operation on one account's entries, run on a worker thread.
type Op<T> = Box<dyn FnOnce(&Entries) -> Result<T, Failure> + Send>;

/// Credential records in a `keyring-core` store.
#[derive(Debug)]
pub struct KeyringStore {
    store: PlatformStore,
    max_entry_bytes: usize,
    timeout: Duration,
    deadline: Option<Instant>,
}

/// Starts the keyring with `start` under `timeout`. A store that fails to
/// start is [`KeyringStart::Unavailable`]; a locked store or a timeout is
/// an error, never a reason to fall back.
///
/// # Errors
/// `credential_store` for a store that refuses access, `keyring_timeout`.
pub fn open(
    start: StartFn,
    max_entry_bytes: usize,
    timeout: Duration,
    command_deadline: Option<Instant>,
) -> Result<KeyringStart, Error> {
    deadline::operation(command_deadline, || {
        let budget = clipped_wait(timeout, command_deadline, Instant::now());
        match worker::run_within(Box::new(start), budget.duration) {
            Some(Ok(store)) => Ok(KeyringStart::Ready(Box::new(KeyringStore::new(
                store,
                max_entry_bytes,
                timeout,
                command_deadline,
            )))),
            Some(Err(error @ keyring_core::Error::NoStorageAccess(_))) => {
                Err(keyring_error(&error))
            }
            Some(Err(error)) => Ok(KeyringStart::Unavailable(error.to_string())),
            None => Err(wait_error(budget)),
        }
    })
}

impl KeyringStore {
    /// Records in `store`, at most `max_entry_bytes` per entry, each call
    /// bounded by `timeout`.
    #[must_use]
    pub const fn new(
        store: PlatformStore,
        max_entry_bytes: usize,
        timeout: Duration,
        deadline: Option<Instant>,
    ) -> Self {
        Self {
            store,
            max_entry_bytes,
            timeout,
            deadline,
        }
    }

    /// Runs `op` on the entries of `key` on a worker thread.
    fn within<T: Send + 'static>(&self, key: &Key, op: Op<T>) -> Result<T, Error> {
        let entries = Entries {
            store: Arc::clone(&self.store),
            account: key.account(),
            max_entry_bytes: self.max_entry_bytes,
        };
        deadline::operation(self.deadline, || {
            let budget = clipped_wait(self.timeout, self.deadline, Instant::now());
            match worker::run_within(Box::new(move || op(&entries)), budget.duration) {
                Some(result) => result.map_err(|failure| failure.into_error(key)),
                None => Err(wait_error(budget).retaining_credential_lock()),
            }
        })
    }
}

impl CredentialStore for KeyringStore {
    fn get(&self, key: &Key) -> Result<Option<Vec<u8>>, Error> {
        self.within(key, Box::new(Entries::get_record))
    }

    fn set(&self, key: &Key, record: &[u8]) -> Result<(), Error> {
        store::check_record(key, record)?;
        let record = record.to_vec();
        self.within(key, Box::new(move |entries| entries.set_record(&record)))
    }

    fn delete(&self, key: &Key) -> Result<(), Error> {
        self.within(key, Box::new(Entries::delete_record))
    }
}

/// Why a keyring operation failed, before the key is attached.
#[derive(Debug)]
enum Failure {
    Keyring(keyring_core::Error),
    Corrupt,
    TooLarge,
}

impl Failure {
    fn into_error(self, key: &Key) -> Error {
        match self {
            Self::Keyring(error) => keyring_error(&error),
            Self::Corrupt => store::corrupt(key),
            Self::TooLarge => store::too_large(key),
        }
    }
}

impl From<chunk::Corrupt> for Failure {
    fn from(_: chunk::Corrupt) -> Self {
        Self::Corrupt
    }
}

/// A keyring failure as the user sees it. Only the platform's own reason
/// is shown: other variants may carry stored bytes.
fn keyring_error(error: &keyring_core::Error) -> Error {
    let message = match error {
        keyring_core::Error::NoStorageAccess(cause) => {
            format!("the OS keyring is locked or refused access ({cause}); unlock it and try again")
        }
        keyring_core::Error::PlatformFailure(cause) => format!("the OS keyring failed: {cause}"),
        _ => "the OS keyring rejected the request".to_owned(),
    };
    Error::new(ErrorKind::CredentialStore, message)
}

fn timeout_error(timeout: Duration) -> Error {
    Error::new(
        ErrorKind::KeyringTimeout,
        format!(
            "the OS keyring did not answer within {} s; unlock it, or raise limits.keyring_timeout_secs",
            timeout.as_secs()
        ),
    )
}

fn wait_error(wait: Wait) -> Error {
    match wait.limit {
        Limit::Operation => timeout_error(wait.duration),
        Limit::Command => deadline::timeout(),
    }
}

/// The entries of one account: the main entry and its chunks.
struct Entries {
    store: PlatformStore,
    account: String,
    max_entry_bytes: usize,
}

impl Entries {
    fn read(&self, account: &str) -> Result<Option<Vec<u8>>, Failure> {
        match self
            .store
            .build(SERVICE, account, None)
            .and_then(|entry| entry.get_secret())
        {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => Err(Failure::Keyring(error)),
        }
    }

    fn write(&self, account: &str, bytes: &[u8]) -> Result<(), Failure> {
        self.store
            .build(SERVICE, account, None)
            .and_then(|entry| entry.set_secret(bytes))
            .map_err(Failure::Keyring)
    }

    fn remove(&self, account: &str) -> Result<(), Failure> {
        match self
            .store
            .build(SERVICE, account, None)
            .and_then(|entry| entry.delete_credential())
        {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(error) => Err(Failure::Keyring(error)),
        }
    }

    fn get_record(&self) -> Result<Option<Vec<u8>>, Failure> {
        let head = self
            .read(&self.account)?
            .map(chunk::parse_head)
            .transpose()?;
        match head {
            None => Ok(None),
            Some(Head::Inline(record)) if record.len() > MAX_RECORD_BYTES => Err(Failure::TooLarge),
            Some(Head::Inline(record)) => Ok(Some(record)),
            Some(Head::Chunked(manifest)) => self.read_chunks(&manifest).map(Some),
        }
    }

    fn read_chunks(&self, manifest: &Manifest) -> Result<Vec<u8>, Failure> {
        let mut parts = Vec::with_capacity(manifest.count);
        for index in 0..manifest.count {
            let account = chunk::chunk_account(&self.account, manifest.slot, index);
            // Checked before it is kept, so damaged entries cannot pile up.
            let part = self
                .read(&account)?
                .filter(|part| part.len() <= CHUNK_BYTES);
            parts.push(part.ok_or(Failure::Corrupt)?);
        }
        Ok(chunk::join(manifest, &parts)?)
    }

    /// The manifest the main entry holds now, if any. A damaged main entry
    /// counts as none, so a new record can still replace it.
    fn committed(&self) -> Result<Option<Manifest>, Failure> {
        let head = self.read(&self.account)?.map(chunk::parse_head);
        Ok(match head {
            Some(Ok(Head::Chunked(manifest))) => Some(manifest),
            _ => None,
        })
    }

    /// Writes the record, then deletes the chunks the old manifest named.
    /// A chunked record goes to the other slot, cleared first of any
    /// orphans, and the manifest is written last: until then the old
    /// record stays readable.
    fn set_record(&self, record: &[u8]) -> Result<(), Failure> {
        let committed = self.committed()?;
        if record.len() <= self.max_entry_bytes {
            self.write(&self.account, record)?;
        } else {
            let slot = committed
                .as_ref()
                .map_or(Slot::Zero, |manifest| manifest.slot.other());
            self.clear(slot, MAX_CHUNKS)?;
            for (index, part) in record.chunks(CHUNK_BYTES).enumerate() {
                self.write(&chunk::chunk_account(&self.account, slot, index), part)?;
            }
            self.write(&self.account, &Manifest::describe(record, slot).encode())?;
        }
        committed.map_or(Ok(()), |manifest| self.clear(manifest.slot, manifest.count))
    }

    /// Deletes the main entry first, so a crash leaves no readable record,
    /// then every chunk of both slots: an inline write that crashed before
    /// its cleanup leaves chunks no manifest names, and they must not
    /// outlive a logout.
    fn delete_record(&self) -> Result<(), Failure> {
        self.remove(&self.account)?;
        self.clear(Slot::Zero, MAX_CHUNKS)?;
        self.clear(Slot::One, MAX_CHUNKS)
    }

    fn clear(&self, slot: Slot, count: usize) -> Result<(), Failure> {
        for index in 0..count {
            self.remove(&chunk::chunk_account(&self.account, slot, index))?;
        }
        Ok(())
    }
}
