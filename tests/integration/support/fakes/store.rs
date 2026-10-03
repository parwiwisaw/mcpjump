//! `CredentialStore` and `StoreOpener` doubles.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::Path;
use std::rc::Rc;

use tokio::time::Instant;

use mcpjump::config::limits::Limits;
use mcpjump::error::{Error, ErrorKind};
use mcpjump::store::file::FileStore;
use mcpjump::store::select::{KeyringStart, StoreOpener};
use mcpjump::store::{self, CredentialStore, Key};

/// Records in memory, shared by every clone.
#[derive(Debug, Clone, Default)]
pub(crate) struct MemoryStore {
    records: Rc<RefCell<BTreeMap<String, Vec<u8>>>>,
}

impl MemoryStore {
    /// The stored accounts, in order.
    pub(crate) fn accounts(&self) -> Vec<String> {
        self.records.borrow().keys().cloned().collect()
    }
}

impl CredentialStore for MemoryStore {
    fn get(&self, key: &Key) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.records.borrow().get(&key.account()).cloned())
    }

    fn set(&self, key: &Key, record: &[u8]) -> Result<(), Error> {
        store::check_record(key, record)?;
        self.records
            .borrow_mut()
            .insert(key.account(), record.to_vec());
        Ok(())
    }

    fn delete(&self, key: &Key) -> Result<(), Error> {
        self.records.borrow_mut().remove(&key.account());
        Ok(())
    }
}

/// A store whose every call fails with one error kind.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FailingStore(pub(crate) ErrorKind);

impl FailingStore {
    fn error(self) -> Error {
        Error::new(self.0, "fake store failure")
    }
}

impl CredentialStore for FailingStore {
    fn get(&self, _key: &Key) -> Result<Option<Vec<u8>>, Error> {
        Err(self.error())
    }

    fn set(&self, _key: &Key, _record: &[u8]) -> Result<(), Error> {
        Err(self.error())
    }

    fn delete(&self, _key: &Key) -> Result<(), Error> {
        Err(self.error())
    }
}

/// What the fake keyring does when opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyringMode {
    /// Ready, backed by the opener's [`MemoryStore`].
    Ready,
    /// Ready, but every call fails with this kind.
    Broken(ErrorKind),
    /// Not available on this machine.
    Unavailable,
    /// Opening fails with this kind (locked, timed out).
    Refuses(ErrorKind),
}

/// A `StoreOpener` whose keyring is scripted and whose file store is real.
#[derive(Debug)]
pub(crate) struct FakeOpener {
    mode: Cell<KeyringMode>,
    keyring: MemoryStore,
    opened: Cell<usize>,
}

impl Default for FakeOpener {
    fn default() -> Self {
        Self {
            mode: Cell::new(KeyringMode::Ready),
            keyring: MemoryStore::default(),
            opened: Cell::new(0),
        }
    }
}

impl FakeOpener {
    /// Sets what the next opens do.
    pub(crate) fn set_mode(&self, mode: KeyringMode) {
        self.mode.set(mode);
    }

    /// The records in the fake keyring.
    pub(crate) fn keyring(&self) -> &MemoryStore {
        &self.keyring
    }

    /// How many times the keyring was opened.
    pub(crate) fn opened(&self) -> usize {
        self.opened.get()
    }
}

impl StoreOpener for FakeOpener {
    fn keyring(&self, _limits: &Limits, _deadline: Option<Instant>) -> Result<KeyringStart, Error> {
        self.opened.set(self.opened.get() + 1);
        match self.mode.get() {
            KeyringMode::Ready => Ok(KeyringStart::Ready(Box::new(self.keyring.clone()))),
            KeyringMode::Broken(kind) => Ok(KeyringStart::Ready(Box::new(FailingStore(kind)))),
            KeyringMode::Unavailable => Ok(KeyringStart::Unavailable("no keyring daemon".into())),
            KeyringMode::Refuses(kind) => Err(Error::new(kind, "keyring refused")),
        }
    }

    fn file(&self, config_dir: &Path) -> Box<dyn CredentialStore> {
        Box::new(FileStore::new(config_dir))
    }
}
