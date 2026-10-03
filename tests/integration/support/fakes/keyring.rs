//! A `keyring-core` store in memory that can fail or stall on demand, to
//! test `KeyringStore` against the same API the platform stores implement.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use keyring_core::api::{CredentialApi, CredentialStoreApi};
use keyring_core::{Entry, Error, Result};
use mcpjump::store::keyring::PlatformStore;

/// What the fake does, shared by the store and its entries.
#[derive(Debug, Default)]
pub(crate) struct State {
    /// Stored secrets by account.
    pub(crate) entries: BTreeMap<String, Vec<u8>>,
    /// Writes and deletes allowed before every later one fails.
    pub(crate) writes_left: Option<usize>,
    /// The error every read, write and delete returns.
    pub(crate) fail: Option<fn() -> Error>,
    /// Accounts whose every call fails, to fault one chunk alone.
    pub(crate) broken: BTreeSet<String>,
    /// How long every call sleeps first.
    pub(crate) delay: Duration,
}

/// The fake store.
#[derive(Debug, Clone, Default)]
pub(crate) struct FakeKeyring {
    state: Arc<Mutex<State>>,
}

impl FakeKeyring {
    /// The shared state, to script or inspect.
    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    /// The store as `KeyringStore` takes it.
    pub(crate) fn platform(&self) -> PlatformStore {
        Arc::new(self.clone())
    }

    /// The stored accounts, in order.
    pub(crate) fn accounts(&self) -> Vec<String> {
        self.state().entries.keys().cloned().collect()
    }
}

impl CredentialStoreApi for FakeKeyring {
    fn vendor(&self) -> String {
        "mcpjump test".into()
    }

    fn id(&self) -> String {
        "fake".into()
    }

    fn build(
        &self,
        _service: &str,
        user: &str,
        _modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        Ok(Entry::new_with_credential(Arc::new(FakeEntry {
            state: Arc::clone(&self.state),
            account: user.to_owned(),
        })))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug)]
struct FakeEntry {
    state: Arc<Mutex<State>>,
    account: String,
}

impl FakeEntry {
    /// Sleeps, then applies the scripted failure.
    fn enter(&self, writes: bool) -> Result<MutexGuard<'_, State>> {
        let delay = self.state.lock().unwrap().delay;
        thread::sleep(delay);
        let mut state = self.state.lock().unwrap();
        if let Some(fail) = state.fail {
            return Err(fail());
        }
        if state.broken.contains(&self.account) {
            return Err(Error::PlatformFailure("injected fault".into()));
        }
        if writes {
            match state.writes_left {
                Some(0) => return Err(Error::PlatformFailure("injected crash".into())),
                Some(left) => state.writes_left = Some(left - 1),
                None => {}
            }
        }
        Ok(state)
    }
}

impl CredentialApi for FakeEntry {
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        let mut state = self.enter(true)?;
        state.entries.insert(self.account.clone(), secret.to_vec());
        Ok(())
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        let state = self.enter(false)?;
        state
            .entries
            .get(&self.account)
            .cloned()
            .ok_or(Error::NoEntry)
    }

    fn delete_credential(&self) -> Result<()> {
        let mut state = self.enter(true)?;
        state
            .entries
            .remove(&self.account)
            .map(drop)
            .ok_or(Error::NoEntry)
    }

    fn get_credential(&self) -> Result<Option<Arc<keyring_core::api::Credential>>> {
        Ok(None)
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some(("mcpjump".into(), self.account.clone()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
