//! The `CredentialStore` contract, run against every implementation.

use std::time::Duration;

use mcpjump::config::limits::Limits;
use mcpjump::config::validate::ServerName;
use mcpjump::error::ErrorKind;
use mcpjump::store::file::FileStore;
use mcpjump::store::keyring::KeyringStore;
use mcpjump::store::select::{KeyringStart, StoreOpener};
use mcpjump::store::system::SystemStores;
use mcpjump::store::{CredentialStore, Key, MAX_RECORD_BYTES, RecordKind};

use crate::support::fakes::keyring::FakeKeyring;
use crate::support::fakes::store::MemoryStore;

/// A JSON-object-looking record of exactly `len` bytes.
pub(crate) fn record(len: usize, fill: u8) -> Vec<u8> {
    let mut bytes = vec![fill; len];
    bytes[0] = b'{';
    bytes
}

pub(crate) fn key(server: &str, kind: RecordKind) -> Key {
    Key::new(ServerName::parse(server).unwrap(), kind)
}

/// Every behaviour a store must have. Leaves nothing stored under `server`.
fn contract(store: &dyn CredentialStore, server: &str) {
    let tokens = key(server, RecordKind::Tokens);
    let registration = key(server, RecordKind::Registration);
    let other = key(&format!("{server}-other"), RecordKind::Tokens);

    assert_eq!(store.get(&tokens).unwrap(), None);
    store.delete(&tokens).unwrap();

    store.set(&tokens, b"{\"a\":1}").unwrap();
    assert_eq!(store.get(&tokens).unwrap(), Some(b"{\"a\":1}".to_vec()));
    assert_eq!(store.get(&registration).unwrap(), None);
    assert_eq!(store.get(&other).unwrap(), None);

    let largest = record(MAX_RECORD_BYTES, b'x');
    store.set(&tokens, &largest).unwrap();
    assert_eq!(store.get(&tokens).unwrap(), Some(largest));
    store.set(&tokens, b"{}").unwrap();
    assert_eq!(store.get(&tokens).unwrap(), Some(b"{}".to_vec()));

    let too_large = store.set(&tokens, &record(MAX_RECORD_BYTES + 1, b'x'));
    assert_eq!(too_large.unwrap_err().kind(), ErrorKind::CredentialTooLarge);
    for bad in [&b""[..], b"[]", b"\0mcpjump-chunks/1 0 1 00"] {
        let error = store.set(&tokens, bad).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
    }
    assert_eq!(store.get(&tokens).unwrap(), Some(b"{}".to_vec()));

    store.set(&registration, b"{\"r\":1}").unwrap();
    store.delete(&tokens).unwrap();
    assert_eq!(store.get(&tokens).unwrap(), None);
    assert_eq!(
        store.get(&registration).unwrap(),
        Some(b"{\"r\":1}".to_vec())
    );
    store.delete(&registration).unwrap();
    assert_eq!(store.get(&registration).unwrap(), None);
}

#[test]
fn memory_store_meets_the_contract() {
    contract(&MemoryStore::default(), "demo");
}

#[test]
fn file_store_meets_the_contract() {
    let dir = tempfile::tempdir().unwrap();
    contract(&FileStore::new(dir.path()), "demo");
}

#[test]
fn keyring_store_meets_the_contract_with_windows_sized_entries() {
    let fake = FakeKeyring::default();
    let store = KeyringStore::new(fake.platform(), 2560, Duration::from_secs(5));
    contract(&store, "demo");
    assert_eq!(fake.accounts(), Vec::<String>::new());
}

#[test]
fn keyring_store_meets_the_contract_with_one_entry_per_record() {
    let fake = FakeKeyring::default();
    let store = KeyringStore::new(fake.platform(), MAX_RECORD_BYTES, Duration::from_secs(5));
    contract(&store, "demo");
    assert_eq!(fake.accounts(), Vec::<String>::new());
}

#[test]
fn system_file_store_meets_the_contract() {
    let dir = tempfile::tempdir().unwrap();
    contract(SystemStores.file(dir.path()).as_ref(), "demo");
}

/// Starting the store touches no item, so it runs everywhere: a machine
/// without a keyring reports it as unavailable, never as an error.
#[test]
fn the_os_keyring_starts_or_is_unavailable() {
    match SystemStores.keyring(&Limits::default()).unwrap() {
        KeyringStart::Ready(_) => {}
        KeyringStart::Unavailable(reason) => assert!(!reason.is_empty()),
    }
}

/// Uses this machine's keyring: ignored by default, run by the coverage
/// jobs, which set one up on every OS.
#[test]
#[ignore = "uses the OS keyring"]
fn os_keyring_meets_the_contract() {
    let limits = Limits::default();
    let KeyringStart::Ready(store) = SystemStores.keyring(&limits).unwrap() else {
        panic!("no OS keyring on this machine");
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    contract(
        store.as_ref(),
        &format!("test-{}-{nanos}", std::process::id()),
    );
}
