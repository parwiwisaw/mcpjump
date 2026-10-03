//! `login` and `logout` when something on the way fails: names, client
//! registration, the callback port, and the credential store and its lock.

use std::fs;
use std::net::TcpListener;
use std::time::Duration;

use mcpjump::config::validate::ServerName;
use mcpjump::error::ErrorKind;
use mcpjump::files::FileLock;
use mcpjump::store::file::FileStore;
use mcpjump::store::lock;
use mcpjump::store::record::{self, RegistrationRecord};
use mcpjump::store::{CredentialStore, RecordKind};
use serde_json::json;
use url::Url;

use crate::store_contract::key;
use crate::support::Harness;
use crate::support::auth::{
    NAME, client, failure, harness, reply, run_watched, seed, stored, unauthorized,
};
use crate::support::fakes::browser::Behavior;
use crate::support::fakes::connector::FakeConnector;
use crate::support::fakes::store::KeyringMode;
use crate::support::fakes::user::Act;
use crate::support::oauth_server::{Doc, OAuthServer, Registration, Script};

/// Limits under which a held lock times out quickly.
const QUICK: &str = "[limits]\nrequest_timeout_secs = 1\nlock_wait_secs = 2\n";

#[test]
fn dropping_an_oauth_fixture_closes_its_listener_and_runtime() {
    for _ in 0..128 {
        let server = OAuthServer::start(Script::default());
        let address = std::net::SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            server.base.port().unwrap(),
        );
        drop(server);
        assert!(std::net::TcpListener::bind(address).is_ok());
    }
}

/// A harness whose probe gets a 401 and whose browser follows the login.
fn ready(server: &OAuthServer, extra: &str) -> Harness {
    let mut h = harness(server, extra);
    h.connector = FakeConnector::answer(Err(unauthorized(server)));
    h.browser.set(Behavior::Follow);
    h
}

fn login(h: &Harness) -> (String, String) {
    failure(&run_watched(h, &["login", "demo"], Act::Wait))
}

/// A loopback port held open until the listener drops.
fn busy_port() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// `client`, with its redirect URI on `port`.
fn client_on(server: &OAuthServer, port: u16) -> RegistrationRecord {
    RegistrationRecord {
        redirect_uri: Url::parse(&format!("http://127.0.0.1:{port}/callback")).unwrap(),
        ..client(server)
    }
}

/// A port nothing listens on, so a saved registration there is reused.
fn free_port() -> u16 {
    busy_port().1
}

fn hold_lock(h: &Harness) -> FileLock {
    let name = ServerName::parse(NAME).unwrap();
    lock::server_lock(h.home.path(), &name, Duration::ZERO).unwrap()
}

#[test]
fn names_are_checked_before_anything_else() {
    let server = OAuthServer::start(Script::default());
    let h = ready(&server, "");
    for (args, kind) in [
        (&["login", "nope"][..], "unknown_server"),
        (&["login", "Bad Name"], "invalid_name"),
        (&["logout", "Bad Name"], "invalid_name"),
        (&["run", "nope", "echo"], "unknown_server"),
        (&["tools", "nope"], "unknown_server"),
    ] {
        assert_eq!(h.run(args).error_kind(), kind, "{args:?}");
    }
    assert!(server.paths().is_empty());
}

#[test]
fn a_text_login_prints_the_url_as_text() {
    let server = OAuthServer::start(Script::default());
    let h = ready(&server, "");
    let outcome = run_watched(&h, &["--output", "text", "login", "demo"], Act::Wait);
    assert_eq!(outcome.code, 0, "{}", outcome.err);
    assert!(
        outcome.err.starts_with("To log in, open:\n  http://"),
        "{}",
        outcome.err
    );
}

#[test]
fn a_failed_registration_fails_the_login() {
    for (registration, expected) in [
        (Registration::Fail, "http_status"),
        (Registration::Garbage, "protocol_error"),
        (Registration::Unusable, "protocol_error"),
    ] {
        let server = OAuthServer::start(Script {
            registration,
            ..Script::default()
        });
        let (kind, message) = login(&ready(&server, ""));
        assert_eq!(kind, expected, "{registration:?}: {message}");
        assert!(server.to("/authorize").is_empty());
    }
}

#[test]
fn an_unusable_registration_names_the_server() {
    let server = OAuthServer::start(Script {
        registration: Registration::Unusable,
        ..Script::default()
    });
    let (_, message) = login(&ready(&server, ""));
    let origin = server.base.as_str().trim_end_matches('/').to_owned();
    assert_eq!(
        message,
        format!("{origin} returned an unusable client registration")
    );
}

#[test]
fn a_registration_endpoint_nothing_answers_is_a_network_error() {
    let server = OAuthServer::start(Script {
        metadata_doc: Doc::Patched(|d| {
            d["registration_endpoint"] = json!("http://127.0.0.1:1/register");
        }),
        ..Script::default()
    });
    assert_eq!(login(&ready(&server, "")).0, "network");
}

#[test]
fn a_slow_secret_registration_times_out() {
    let server = OAuthServer::start(Script {
        registration: Registration::SlowSecret,
        ..Script::default()
    });
    let (kind, _) = login(&ready(&server, "[limits]\nauth_network_budget_secs = 1\n"));
    assert_eq!(kind, "auth_timeout");
    assert_eq!(server.to("/register").len(), 2);
}

#[test]
fn a_busy_callback_port_fails_the_login() {
    let server = OAuthServer::start(Script::default());
    let (_held, port) = busy_port();
    for extra in [
        format!("client_id = \"pre-client\"\ncallback_port = {port}\n"),
        format!("callback_port = {port}\n"),
    ] {
        let (kind, message) = login(&ready(&server, &extra));
        assert_eq!(kind, "network");
        assert_eq!(
            message,
            format!("cannot listen for the login callback on 127.0.0.1:{port}")
        );
    }
}

#[test]
fn a_saved_registration_on_a_busy_port_is_replaced() {
    let server = OAuthServer::start(Script::default());
    let (_held, port) = busy_port();
    let h = ready(&server, "credentials = \"keyring\"\n");
    seed(
        h.stores.keyring(),
        RecordKind::Registration,
        &client_on(&server, port),
    );
    reply(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert_eq!(server.to("/register").len(), 1);
    let saved: RegistrationRecord = stored(h.stores.keyring(), RecordKind::Registration).unwrap();
    assert_ne!(saved.redirect_uri.port(), Some(port));
}

#[test]
fn a_client_metadata_document_that_cannot_be_read_fails() {
    let server = OAuthServer::start(Script {
        cimd: true,
        ..Script::default()
    });
    let metadata = server
        .base
        .join(".well-known/oauth-authorization-server")
        .unwrap();
    for (document, expected) in [
        ("http://127.0.0.1:1/client.json".to_owned(), "network"),
        (metadata.to_string(), "protocol_error"),
    ] {
        let extra = format!("[settings]\nclient_metadata_url = \"{document}\"\n");
        assert_eq!(login(&ready(&server, &extra)).0, expected, "{document}");
    }
}

#[test]
fn a_keyring_that_fails_fails_the_login() {
    let server = OAuthServer::start(Script::default());
    for mode in [
        KeyringMode::Refuses(ErrorKind::CredentialStore),
        KeyringMode::Broken(ErrorKind::CredentialStore),
    ] {
        let h = ready(&server, "credentials = \"keyring\"\n");
        h.stores.set_mode(mode);
        assert_eq!(login(&h).0, "credential_store", "{mode:?}");
    }
    let h = ready(&server, "[settings]\ncredential_store = \"keyring\"\n");
    h.stores
        .set_mode(KeyringMode::Refuses(ErrorKind::CredentialStore));
    assert_eq!(login(&h).0, "credential_store");
    assert!(server.to("/authorize").is_empty());
}

#[test]
fn a_held_lock_fails_saving_the_registration() {
    let server = OAuthServer::start(Script::default());
    let h = ready(&server, QUICK);
    let held = hold_lock(&h);
    assert_eq!(login(&h).0, "credential_lock_timeout");
    drop(held);
    assert!(server.to("/authorize").is_empty());
}

#[test]
fn a_held_lock_fails_saving_the_tokens() {
    let server = OAuthServer::start(Script::default());
    let h = ready(&server, &format!("credentials = \"keyring\"\n{QUICK}"));
    seed(
        h.stores.keyring(),
        RecordKind::Registration,
        &client_on(&server, free_port()),
    );
    let held = hold_lock(&h);
    assert_eq!(login(&h).0, "credential_lock_timeout");
    drop(held);
    assert_eq!(server.to("/token").len(), 1);
    assert!(server.to("/register").is_empty());
}

#[test]
fn unreadable_stored_tokens_fail_the_login() {
    let server = OAuthServer::start(Script::default());
    let h = ready(&server, "credentials = \"file\"\n");
    let store = FileStore::new(h.home.path());
    store
        .set(
            &key(NAME, RecordKind::Registration),
            &record::encode(&client_on(&server, free_port())),
        )
        .unwrap();
    fs::create_dir(store.path(&key(NAME, RecordKind::Tokens))).unwrap();
    assert_eq!(login(&h).0, "credential_store");
    assert!(server.to("/authorize").is_empty());
}

#[test]
fn a_logout_whose_store_or_lock_fails_fails() {
    let server = OAuthServer::start(Script::default());
    let h = ready(&server, &format!("credentials = \"keyring\"\n{QUICK}"));
    h.stores
        .set_mode(KeyringMode::Refuses(ErrorKind::CredentialStore));
    assert_eq!(h.run(&["logout", "demo"]).error_kind(), "credential_store");
    h.stores.set_mode(KeyringMode::Ready);
    let held = hold_lock(&h);
    assert_eq!(
        h.run(&["logout", "demo"]).error_kind(),
        "credential_lock_timeout"
    );
    drop(held);
}
