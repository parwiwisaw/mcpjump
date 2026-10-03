//! `KeyringStore` over a fake `keyring-core` store: chunking, crash safety,
//! error mapping and timeouts.

use std::thread;
use std::time::Duration;

use keyring_core::Error as KeyringError;
use mcpjump::error::{Error, ErrorKind};
use mcpjump::store::chunk::{Manifest, Slot};
use mcpjump::store::keyring::{self, KeyringStore, PlatformStore};
use mcpjump::store::select::KeyringStart;
use mcpjump::store::{CredentialStore, MAX_RECORD_BYTES, RecordKind};

use crate::store_contract::{key, record};
use crate::support::fakes::keyring::FakeKeyring;

const WINDOWS_ENTRY: usize = 2560;
const MAIN: &str = "demo/tokens";

fn windows_store(fake: &FakeKeyring) -> KeyringStore {
    KeyringStore::new(fake.platform(), WINDOWS_ENTRY, Duration::from_secs(5))
}

fn tokens() -> mcpjump::store::Key {
    key("demo", RecordKind::Tokens)
}

fn chunks(fake: &FakeKeyring) -> Vec<String> {
    fake.accounts()
        .into_iter()
        .filter(|account| account.contains('@'))
        .collect()
}

#[test]
fn a_record_that_fits_one_entry_is_stored_inline() {
    let fake = FakeKeyring::default();
    let store = windows_store(&fake);
    let fits = record(WINDOWS_ENTRY, b'a');
    store.set(&tokens(), &fits).unwrap();
    assert_eq!(fake.accounts(), [MAIN]);
    assert_eq!(fake.state().entries[MAIN], fits);
}

#[test]
fn one_byte_more_is_chunked_behind_a_manifest() {
    let fake = FakeKeyring::default();
    let store = windows_store(&fake);
    let over = record(WINDOWS_ENTRY + 1, b'b');
    store.set(&tokens(), &over).unwrap();
    assert_eq!(chunks(&fake), ["demo/tokens@0#0", "demo/tokens@0#1"]);
    let manifest = Manifest::describe(&over, Slot::Zero).encode();
    assert_eq!(fake.state().entries[MAIN], manifest);
    assert_eq!(store.get(&tokens()).unwrap(), Some(over));
}

#[test]
fn the_largest_record_uses_every_chunk() {
    let fake = FakeKeyring::default();
    let store = windows_store(&fake);
    let largest = record(MAX_RECORD_BYTES, b'c');
    store.set(&tokens(), &largest).unwrap();
    assert_eq!(chunks(&fake).len(), 16);
    assert_eq!(store.get(&tokens()).unwrap(), Some(largest));
}

#[test]
fn rewrites_alternate_slots_and_leave_one_generation() {
    let fake = FakeKeyring::default();
    let store = windows_store(&fake);
    let big = record(9000, b'd');
    let smaller = record(3000, b'e');
    store.set(&tokens(), &big).unwrap();
    store.set(&tokens(), &smaller).unwrap();
    assert_eq!(chunks(&fake), ["demo/tokens@1#0", "demo/tokens@1#1"]);
    assert_eq!(store.get(&tokens()).unwrap(), Some(smaller));
    store.set(&tokens(), &big).unwrap();
    assert_eq!(chunks(&fake).len(), 5);
    assert!(chunks(&fake).iter().all(|account| account.contains("@0#")));
    store.set(&tokens(), b"{}").unwrap();
    assert_eq!(fake.accounts(), [MAIN]);
}

#[test]
fn delete_removes_the_record_and_every_chunk() {
    let fake = FakeKeyring::default();
    let store = windows_store(&fake);
    store.set(&tokens(), &record(9000, b'f')).unwrap();
    fake.state()
        .entries
        .insert("demo/tokens@1#15".into(), b"orphan".to_vec());
    store.delete(&tokens()).unwrap();
    assert_eq!(fake.accounts(), Vec::<String>::new());
}

/// Fails the write at every step in turn, then checks a restart reads the
/// last committed record and the next write leaves no orphans.
#[test]
fn a_crash_at_any_write_step_keeps_the_committed_record() {
    let cases = [
        (record(9000, b'o'), record(5000, b'n')),
        (record(5000, b'o'), record(100, b'n')),
        (record(100, b'o'), record(5000, b'n')),
    ];
    for (old, new) in cases {
        for step in 0..40 {
            let fake = FakeKeyring::default();
            let store = windows_store(&fake);
            store.set(&tokens(), &old).unwrap();
            fake.state().writes_left = Some(step);
            let result = store.set(&tokens(), &new);
            fake.state().writes_left = None;
            let read = store.get(&tokens()).unwrap().unwrap();
            match result {
                Ok(()) => assert_eq!(read, new),
                Err(error) => {
                    assert_eq!(error.kind(), ErrorKind::CredentialStore);
                    assert!(read == old || read == new, "step {step}");
                }
            }
            let third = record(7000, b't');
            store.set(&tokens(), &third).unwrap();
            store.set(&tokens(), &third).unwrap();
            assert_eq!(fake.accounts().len(), 5, "step {step}");
        }
    }
}

#[test]
fn a_damaged_manifest_or_missing_chunk_is_reported_and_replaceable() {
    let fake = FakeKeyring::default();
    let store = windows_store(&fake);
    fake.state()
        .entries
        .insert(MAIN.into(), b"\0mcpjump-chunks/1 9".to_vec());
    let damaged = store.get(&tokens()).unwrap_err();
    assert_eq!(damaged.kind(), ErrorKind::CredentialInvalid);
    assert!(damaged.message().contains("mcpjump logout demo"));
    store.set(&tokens(), &record(3000, b'g')).unwrap();
    fake.state().entries.remove("demo/tokens@0#1");
    let missing = store.get(&tokens()).unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::CredentialInvalid);
    store.delete(&tokens()).unwrap();
    assert_eq!(fake.accounts(), Vec::<String>::new());
}

#[test]
fn a_chunk_that_does_not_match_its_manifest_is_damaged() {
    let fake = FakeKeyring::default();
    let store = windows_store(&fake);
    store.set(&tokens(), &record(3000, b'j')).unwrap();
    fake.state()
        .entries
        .get_mut("demo/tokens@0#1")
        .unwrap()
        .push(b'j');
    let error = store.get(&tokens()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
}

#[test]
fn an_oversized_chunk_is_damaged() {
    let fake = FakeKeyring::default();
    let store = windows_store(&fake);
    store.set(&tokens(), &record(3000, b'l')).unwrap();
    fake.state()
        .entries
        .insert("demo/tokens@0#0".into(), vec![b'l'; 64 * 1024]);
    let error = store.get(&tokens()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CredentialInvalid);
}

/// Fails the delete at every step in turn: the record is then either still
/// whole or gone, and a second delete leaves nothing behind.
#[test]
fn a_delete_cut_short_at_any_step_is_finished_by_the_next() {
    let old = record(9000, b'm');
    for step in 0..40 {
        let fake = FakeKeyring::default();
        let store = windows_store(&fake);
        store.set(&tokens(), &old).unwrap();
        fake.state().writes_left = Some(step);
        let result = store.delete(&tokens());
        fake.state().writes_left = None;
        let read = store.get(&tokens()).unwrap();
        if result.is_ok() {
            assert_eq!(read, None, "step {step}");
        } else {
            assert!(read.is_none() || read.as_ref() == Some(&old), "step {step}");
        }
        store.delete(&tokens()).unwrap();
        assert_eq!(fake.accounts(), Vec::<String>::new(), "step {step}");
    }
}

#[test]
fn a_chunk_the_keyring_cannot_reach_fails_reads_and_deletes() {
    let fake = FakeKeyring::default();
    let store = windows_store(&fake);
    store.set(&tokens(), &record(3000, b'k')).unwrap();
    fake.state().broken.insert("demo/tokens@0#1".into());
    for error in [
        store.get(&tokens()).unwrap_err(),
        store.delete(&tokens()).unwrap_err(),
    ] {
        assert_eq!(error.kind(), ErrorKind::CredentialStore);
    }
    assert!(!fake.accounts().contains(&MAIN.to_owned()));
}

#[test]
fn an_oversized_inline_entry_is_too_large() {
    let fake = FakeKeyring::default();
    let store = windows_store(&fake);
    fake.state()
        .entries
        .insert(MAIN.into(), record(MAX_RECORD_BYTES + 1, b'h'));
    let error = store.get(&tokens()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CredentialTooLarge);
}

fn locked() -> KeyringError {
    KeyringError::NoStorageAccess("user canceled".into())
}

fn platform() -> KeyringError {
    KeyringError::PlatformFailure("daemon crashed".into())
}

fn secret_bearing() -> KeyringError {
    KeyringError::BadEncoding(b"secret-token".to_vec())
}

type Op = fn(&KeyringStore) -> Result<(), Error>;

fn failure(fail: fn() -> KeyringError, op: Op) -> Error {
    let fake = FakeKeyring::default();
    let store = windows_store(&fake);
    store.set(&tokens(), &record(3000, b'i')).unwrap();
    fake.state().fail = Some(fail);
    op(&store).unwrap_err()
}

#[test]
fn keyring_errors_name_the_cause_but_never_stored_bytes() {
    let ops: [Op; 3] = [
        |store| store.get(&tokens()).map(drop),
        |store| store.set(&tokens(), b"{}"),
        |store| store.delete(&tokens()),
    ];
    for op in ops {
        let error = failure(locked, op);
        assert_eq!(error.kind(), ErrorKind::CredentialStore);
        assert!(
            error
                .message()
                .contains("locked or refused access (user canceled)")
        );
        assert!(
            failure(platform, op)
                .message()
                .contains("failed: daemon crashed")
        );
        let hidden = failure(secret_bearing, op);
        assert_eq!(hidden.message(), "the OS keyring rejected the request");
    }
}

#[test]
fn a_keyring_that_stalls_times_out() {
    let fake = FakeKeyring::default();
    fake.state().delay = Duration::from_millis(500);
    let store = KeyringStore::new(fake.platform(), WINDOWS_ENTRY, Duration::from_millis(50));
    let error = store.get(&tokens()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::KeyringTimeout);
    assert!(error.message().contains("keyring_timeout_secs"));
}

#[allow(clippy::unnecessary_wraps, reason = "a keyring::StartFn")]
fn ready() -> keyring_core::Result<PlatformStore> {
    Ok(FakeKeyring::default().platform())
}

fn unsupported() -> keyring_core::Result<PlatformStore> {
    Err(KeyringError::NotSupportedByStore(
        "no Secret Service".into(),
    ))
}

fn refused() -> keyring_core::Result<PlatformStore> {
    Err(locked())
}

fn hangs() -> keyring_core::Result<PlatformStore> {
    thread::sleep(Duration::from_millis(500));
    ready()
}

#[test]
fn opening_distinguishes_ready_unavailable_refused_and_stalled() {
    let second = Duration::from_secs(1);
    let store = match keyring::open(ready, WINDOWS_ENTRY, second).unwrap() {
        KeyringStart::Ready(store) => store,
        KeyringStart::Unavailable(reason) => panic!("unavailable: {reason}"),
    };
    store.set(&tokens(), b"{}").unwrap();
    match keyring::open(unsupported, WINDOWS_ENTRY, second).unwrap() {
        KeyringStart::Unavailable(reason) => assert!(reason.contains("no Secret Service")),
        KeyringStart::Ready(_) => panic!("expected unavailable"),
    }
    let refused = keyring::open(refused, WINDOWS_ENTRY, second).unwrap_err();
    assert_eq!(refused.kind(), ErrorKind::CredentialStore);
    let stalled = keyring::open(hangs, WINDOWS_ENTRY, Duration::from_millis(50)).unwrap_err();
    assert_eq!(stalled.kind(), ErrorKind::KeyringTimeout);
}
