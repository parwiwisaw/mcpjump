//! Credentials as the commands see them: `list` and `get` name the backend,
//! and `remove` deletes the credentials before the config entry.

use std::fs;
use std::time::Duration;

use mcpjump::config::document;
use mcpjump::config::model::Backend;
use mcpjump::config::validate::ServerName;
use mcpjump::error::ErrorKind;
use mcpjump::store::file::FileStore;
use mcpjump::store::lock::server_lock;
use mcpjump::store::{CredentialStore, RecordKind};
use serde_json::json;
use toml_edit::DocumentMut;

use crate::store_contract::key;
use crate::support::Harness;
use crate::support::fakes::store::KeyringMode;

const URL: &str = "https://example.com/mcp";

fn with_servers(h: &Harness) {
    h.write_config(&format!(
        "[servers.kr]\nurl = \"{URL}\"\ncredentials = \"keyring\"\n\
         [servers.fl]\nurl = \"{URL}\"\ncredentials = \"file\"\n\
         [servers.none]\nurl = \"{URL}\"\n"
    ));
}

fn seed(store: &dyn CredentialStore, server: &str) {
    for kind in RecordKind::ALL {
        store.set(&key(server, kind), b"{}").unwrap();
    }
}

#[test]
fn list_and_get_name_the_backend() {
    let h = Harness::new();
    with_servers(&h);
    let listed = h.run(&["list"]).json();
    let backends: Vec<_> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|server| (server["name"].clone(), server["credentials"].clone()))
        .collect();
    assert_eq!(
        backends,
        [
            (json!("fl"), json!("file (unencrypted)")),
            (json!("kr"), json!("keyring")),
            (json!("none"), json!(null)),
        ]
    );
    assert_eq!(
        h.run(&["get", "fl"]).json()["credentials"],
        "file (unencrypted)"
    );
    assert_eq!(h.run(&["get", "kr"]).json()["credentials"], "keyring");
}

#[test]
fn remove_deletes_keyring_credentials_and_leaves_other_servers() {
    let h = Harness::new();
    with_servers(&h);
    seed(h.stores.keyring(), "kr");
    seed(h.stores.keyring(), "fl");
    assert_eq!(h.run(&["remove", "kr"]).json(), json!({"removed": "kr"}));
    assert_eq!(
        h.stores.keyring().accounts(),
        ["fl/registration", "fl/tokens"]
    );
    assert!(!h.config_text().contains("[servers.kr]"));
}

#[test]
fn remove_deletes_file_credentials_quietly() {
    let h = Harness::new();
    with_servers(&h);
    let files = FileStore::new(h.home.path());
    seed(&files, "fl");
    assert_eq!(h.run(&["remove", "fl"]).json(), json!({"removed": "fl"}));
    let left: Vec<_> = fs::read_dir(h.home.path().join("credentials"))
        .unwrap()
        .collect();
    assert!(left.is_empty());
    assert_eq!(h.stores.opened(), 0);
}

#[test]
fn remove_without_credentials_never_opens_a_store() {
    let h = Harness::new();
    with_servers(&h);
    h.stores
        .set_mode(KeyringMode::Refuses(ErrorKind::KeyringTimeout));
    assert_eq!(
        h.run(&["remove", "none"]).json(),
        json!({"removed": "none"})
    );
    assert_eq!(h.stores.opened(), 0);
}

#[test]
fn remove_keeps_the_entry_when_the_credentials_cannot_be_deleted() {
    for mode in [
        KeyringMode::Broken(ErrorKind::CredentialStore),
        KeyringMode::Refuses(ErrorKind::KeyringTimeout),
        KeyringMode::Unavailable,
    ] {
        let h = Harness::new();
        with_servers(&h);
        h.stores.set_mode(mode);
        let before = h.config_text();
        let outcome = h.run(&["remove", "kr"]);
        assert_eq!(outcome.code, 5);
        assert!(
            outcome.error_kind().starts_with("credential_store")
                || outcome.error_kind() == "keyring_timeout"
        );
        assert_eq!(h.config_text(), before);
    }
}

#[test]
fn remove_waits_for_a_login_holding_the_server_lock_then_gives_up() {
    let h = Harness::new();
    h.write_config(&format!(
        "[limits]\nrequest_timeout_secs = 1\nlock_wait_secs = 2\n\
         [servers.kr]\nurl = \"{URL}\"\ncredentials = \"keyring\"\n"
    ));
    let name = ServerName::parse("kr").unwrap();
    let held = server_lock(h.home.path(), &name, Duration::ZERO, None).unwrap();
    let before = h.config_text();
    let outcome = h.run(&["remove", "kr"]);
    assert_eq!(outcome.error_kind(), "credential_lock_timeout");
    assert_eq!(h.config_text(), before);
    drop(held);
}

#[test]
fn the_recorded_backend_is_read_from_the_document() {
    let demo = ServerName::parse("demo").unwrap();
    let read = |text: &str| document::credentials(&text.parse::<DocumentMut>().unwrap(), &demo);
    assert_eq!(
        read("[servers.demo]\ncredentials = \"file\"\n").unwrap(),
        Some(Backend::File)
    );
    assert_eq!(
        read("[servers.demo]\ncredentials = \"keyring\"\n").unwrap(),
        Some(Backend::Keyring)
    );
    assert_eq!(read("[servers.demo]\n").unwrap(), None);
    for (text, kind) in [
        ("", ErrorKind::UnknownServer),
        ("servers = 1\n", ErrorKind::UnknownServer),
        ("[servers]\ndemo = 1\n", ErrorKind::UnknownServer),
        (
            "[servers.demo]\ncredentials = \"vault\"\n",
            ErrorKind::ConfigInvalid,
        ),
        (
            "[servers.demo]\ncredentials = 1\n",
            ErrorKind::ConfigInvalid,
        ),
    ] {
        assert_eq!(read(text).unwrap_err().kind(), kind, "{text:?}");
    }
}

#[test]
fn the_backend_is_recorded_only_for_a_server_that_exists() {
    let demo = ServerName::parse("demo").unwrap();
    let mut doc = "[servers.demo]\nurl = \"x\"\n"
        .parse::<DocumentMut>()
        .unwrap();
    document::set_credentials(&mut doc, &demo, Backend::File).unwrap();
    assert!(doc.to_string().contains("credentials = \"file\""));
    for text in ["", "servers = 1\n", "[servers]\ndemo = 1\n"] {
        let mut doc = text.parse::<DocumentMut>().unwrap();
        let error = document::set_credentials(&mut doc, &demo, Backend::Keyring).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownServer, "{text:?}");
    }
}
