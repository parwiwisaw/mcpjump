//! A `keyring-core` store in memory that can fail or stall on demand, to
//! test `KeyringStore` against the same API the platform stores implement.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
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
    /// Number of credential calls that actually entered the backend.
    pub(crate) calls: usize,
    /// One matching operation gates once, without retaining the state mutex.
    gate: Option<OperationGate>,
}

/// The fake store.
#[derive(Debug, Clone, Default)]
pub(crate) struct FakeKeyring {
    state: Arc<Mutex<State>>,
}

/// A concrete credential operation, so tests gate only the intended worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    Get,
    Set,
    Delete,
}

#[derive(Debug)]
struct OperationGate {
    account: String,
    operation: Operation,
    reached: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
    completed: mpsc::SyncSender<()>,
}

/// A bounded gate controller. Dropping it also releases a waiting worker.
#[derive(Debug)]
pub(crate) struct Gate {
    reached: mpsc::Receiver<()>,
    release: Option<mpsc::SyncSender<()>>,
    completed: mpsc::Receiver<()>,
}

impl Gate {
    pub(crate) fn wait_reached(&self) {
        self.reached.recv_timeout(Duration::from_secs(5)).unwrap();
    }

    pub(crate) fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.try_send(());
        }
    }

    pub(crate) fn wait_completed(&self) {
        self.completed.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.release();
    }
}

impl FakeKeyring {
    /// The shared state, to script or inspect.
    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    /// Gate a single operation. A get captures its value before announcing readiness.
    pub(crate) fn gate(&self, account: &str, operation: Operation) -> Gate {
        let (reached, received) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let (completed, complete) = mpsc::sync_channel(1);
        let previous = self.state().gate.replace(OperationGate {
            account: account.to_owned(),
            operation,
            reached,
            release: released,
            completed,
        });
        assert!(previous.is_none(), "only one gate per fake may be active");
        Gate {
            reached: received,
            release: Some(release),
            completed: complete,
        }
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
        state.calls = state.calls.saturating_add(1);
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
        let gate = take_gate(&mut state, &self.account, Operation::Set);
        drop(state);
        let gate = wait_gate(gate)?;
        self.state
            .lock()
            .unwrap()
            .entries
            .insert(self.account.clone(), secret.to_vec());
        complete_gate(gate);
        Ok(())
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        let mut state = self.enter(false)?;
        let value = state
            .entries
            .get(&self.account)
            .cloned()
            .ok_or(Error::NoEntry);
        let gate = take_gate(&mut state, &self.account, Operation::Get);
        drop(state);
        let gate = wait_gate(gate)?;
        complete_gate(gate);
        value
    }

    fn delete_credential(&self) -> Result<()> {
        let mut state = self.enter(true)?;
        let gate = take_gate(&mut state, &self.account, Operation::Delete);
        drop(state);
        let gate = wait_gate(gate)?;
        let result = self
            .state
            .lock()
            .unwrap()
            .entries
            .remove(&self.account)
            .map(drop)
            .ok_or(Error::NoEntry);
        complete_gate(gate);
        result
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

fn take_gate(state: &mut State, account: &str, operation: Operation) -> Option<OperationGate> {
    if state
        .gate
        .as_ref()
        .is_some_and(|gate| gate.account == account && gate.operation == operation)
    {
        state.gate.take()
    } else {
        None
    }
}

fn wait_gate(gate: Option<OperationGate>) -> Result<Option<OperationGate>> {
    let Some(gate) = gate else {
        return Ok(None);
    };
    let _ = gate.reached.try_send(());
    match gate.release.recv_timeout(Duration::from_secs(5)) {
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => Ok(Some(gate)),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            complete_gate(Some(gate));
            Err(Error::PlatformFailure(
                "test gate exceeded 5 seconds".into(),
            ))
        }
    }
}

fn complete_gate(gate: Option<OperationGate>) {
    if let Some(gate) = gate {
        let _ = gate.completed.try_send(());
    }
}
