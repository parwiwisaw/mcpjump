//! The real [`StoreOpener`]: the OS keyring and the credential files. Built
//! only in `main.rs`; like the session connector, it is the declared factory
//! for its adapters.

use std::path::Path;

use crate::config::limits::Limits;
use crate::error::Error;
use crate::store::file::FileStore;
use crate::store::select::{KeyringStart, StoreOpener};
use crate::store::{CredentialStore, keyring, platform};

/// Opens the stores of this machine. Constructed only in `main.rs`.
#[derive(Debug)]
pub struct SystemStores;

impl StoreOpener for SystemStores {
    fn keyring(&self, limits: &Limits) -> Result<KeyringStart, Error> {
        keyring::open(
            platform::start,
            platform::MAX_ENTRY_BYTES,
            limits.keyring_timeout(),
        )
    }

    fn file(&self, config_dir: &Path) -> Box<dyn CredentialStore> {
        Box::new(FileStore::new(config_dir))
    }
}
