//! `FileStore` safety: private permissions, no symlinks, bounded reads, and
//! I/O failures reported as `credential_store`.

use std::fs;
use std::time::Duration;

use mcpjump::error::{Error, ErrorKind};
use mcpjump::store::file::FileStore;
use mcpjump::store::lock::{server_lock, with_server_lock};
use mcpjump::store::{CredentialStore, MAX_RECORD_BYTES, RecordKind};

use crate::store_contract::{key, record};

fn tokens() -> mcpjump::store::Key {
    key("demo", RecordKind::Tokens)
}

#[test]
fn records_live_under_credentials_named_by_server_and_kind() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path());
    let registration = key("demo", RecordKind::Registration);
    assert_eq!(
        store.path(&registration),
        dir.path()
            .join("credentials")
            .join("demo.registration.json")
    );
    store.set(&tokens(), b"{}").unwrap();
    assert_eq!(fs::read(store.path(&tokens())).unwrap(), b"{}");
}

#[test]
fn an_oversized_file_is_too_large() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path());
    store.set(&tokens(), b"{}").unwrap();
    fs::write(store.path(&tokens()), record(MAX_RECORD_BYTES + 1, b'x')).unwrap();
    let error = store.get(&tokens()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CredentialTooLarge);
}

#[test]
fn a_directory_in_place_of_a_record_is_a_store_error() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new(dir.path());
    store.set(&tokens(), b"{}").unwrap();
    fs::remove_file(store.path(&tokens())).unwrap();
    fs::create_dir(store.path(&tokens())).unwrap();
    for error in [
        store.get(&tokens()).unwrap_err(),
        store.set(&tokens(), b"{}").unwrap_err(),
        store.delete(&tokens()).unwrap_err(),
    ] {
        assert_eq!(error.kind(), ErrorKind::CredentialStore);
        assert!(error.message().contains("demo.tokens.json"));
    }
}

#[test]
fn a_file_in_place_of_the_credentials_directory_is_a_store_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("credentials"), "").unwrap();
    let error = FileStore::new(dir.path())
        .set(&tokens(), b"{}")
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CredentialStore);
}

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    fn mode(path: &std::path::Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn the_directory_and_files_are_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());
        store.set(&tokens(), b"{}").unwrap();
        assert_eq!(mode(&dir.path().join("credentials")), 0o700);
        assert_eq!(mode(&store.path(&tokens())), 0o600);
    }

    #[test]
    fn a_file_others_can_read_is_refused_with_a_fix() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());
        store.set(&tokens(), b"{}").unwrap();
        let path = store.path(&tokens());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let error = store.get(&tokens()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialStore);
        assert!(error.message().contains("mode 640"));
        assert!(error.message().contains("chmod 600"));
    }

    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());
        store.set(&tokens(), b"{}").unwrap();
        let path = store.path(&tokens());
        fs::remove_file(&path).unwrap();
        let made = std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success());
        let error = store.get(&tokens()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialStore);
        assert!(error.message().contains("not a regular file"));
    }

    fn assert_refused(store: &FileStore, reason: &str) {
        for error in [
            store.get(&tokens()).unwrap_err(),
            store.set(&tokens(), b"{}").unwrap_err(),
            store.delete(&tokens()).unwrap_err(),
        ] {
            assert_eq!(error.kind(), ErrorKind::CredentialStore);
            assert!(error.message().contains(reason), "{}", error.message());
        }
    }

    #[test]
    fn an_unsafe_credentials_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());
        store.set(&tokens(), b"{}").unwrap();
        let credentials = dir.path().join("credentials");
        fs::set_permissions(&credentials, fs::Permissions::from_mode(0o755)).unwrap();
        assert_refused(&store, "chmod 700");

        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&credentials).unwrap();
        symlink(&elsewhere, &credentials).unwrap();
        assert_refused(&store, "not a directory");
    }

    #[test]
    fn an_unreadable_config_directory_is_a_store_error() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        let store = FileStore::new(&home);
        fs::set_permissions(&home, fs::Permissions::from_mode(0o000)).unwrap();
        let error = store.get(&tokens()).unwrap_err();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(error.kind(), ErrorKind::CredentialStore);
    }

    #[test]
    fn a_symlink_is_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());
        store.set(&tokens(), b"{}").unwrap();
        let target = dir.path().join("elsewhere.json");
        fs::write(&target, b"{\"planted\":1}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let path = store.path(&tokens());
        fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        let error = store.get(&tokens()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialStore);
        assert!(error.message().contains("symlink"));
    }
}

#[test]
fn a_held_server_lock_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let name = mcpjump::config::validate::ServerName::parse("demo").unwrap();
    let held = server_lock(dir.path(), &name, Duration::ZERO).unwrap();
    let error = server_lock(dir.path(), &name, Duration::ZERO).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CredentialLockTimeout);
    assert!(dir.path().join("locks/servers/demo.lock").is_file());
    drop(held);
    server_lock(dir.path(), &name, Duration::ZERO).unwrap();
}

#[test]
fn a_keyring_timeout_keeps_the_server_lock_until_exit() {
    let dir = tempfile::tempdir().unwrap();
    let name = mcpjump::config::validate::ServerName::parse("demo").unwrap();
    let wait = Duration::ZERO;
    with_server_lock(dir.path(), &name, wait, &|| Ok(())).unwrap();
    let failed = with_server_lock(dir.path(), &name, wait, &|| {
        Err(Error::new(ErrorKind::CredentialStore, "refused"))
    });
    assert_eq!(failed.unwrap_err().kind(), ErrorKind::CredentialStore);
    server_lock(dir.path(), &name, wait).unwrap();
    let timed_out = with_server_lock(dir.path(), &name, wait, &|| {
        Err(Error::new(ErrorKind::KeyringTimeout, "no answer"))
    });
    assert_eq!(timed_out.unwrap_err().kind(), ErrorKind::KeyringTimeout);
    let held = server_lock(dir.path(), &name, wait).unwrap_err();
    assert_eq!(held.kind(), ErrorKind::CredentialLockTimeout);
}

#[test]
fn an_unusable_lock_directory_is_a_store_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("locks"), "").unwrap();
    let name = mcpjump::config::validate::ServerName::parse("demo").unwrap();
    let error = server_lock(dir.path(), &name, Duration::ZERO).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CredentialStore);
}
