//! Bearer tokens on `tools` and `run`: refreshed before they expire and
//! after a 401, shared with other processes through the server lock, and
//! a 403's scope kept for the next login.

use std::fs;
use std::time::Duration;

use mcpjump::config::model::Generation;
use mcpjump::config::validate::ServerName;
use mcpjump::error::ErrorKind;
use mcpjump::mcp::session::ToolResult;
use mcpjump::store::file::FileStore;
use mcpjump::store::record::{
    self, MAX_PENDING_SCOPE_BYTES, RegistrationRecord, TokenEndpointAuth, TokenRecord,
};
use mcpjump::store::{CredentialStore, RecordKind, lock};
use serde_json::json;

use crate::store_contract::key;
use crate::support::Harness;
use crate::support::auth::{
    NAME, client, failure, harness, needs_scope, refusal, reply, seed, stored, tokens, unauthorized,
};
use crate::support::fakes::clock::START;
use crate::support::fakes::connector::{FakeConnector, FakeSession, tool};
use crate::support::fakes::store::KeyringMode;
use crate::support::fakes::user::Act;
use crate::support::oauth_server::{OAuthServer, Script};

/// The hint every login failure ends with.
const HINT: &str = "; run `mcpjump login demo`";

/// A server whose keyring login holds `tokens` and `client`, and which
/// accepts refresh token `rt-0`.
fn logged_in(script: Script, extra: &str) -> (OAuthServer, Harness) {
    let server = OAuthServer::start(script);
    server.expect_refresh("rt-0");
    let h = harness(&server, &format!("credentials = \"keyring\"\n{extra}"));
    seed(h.stores.keyring(), RecordKind::Tokens, &tokens(&server));
    seed(
        h.stores.keyring(),
        RecordKind::Registration,
        &client(&server),
    );
    (server, h)
}

/// A session listing no tools.
fn listing() -> FakeSession {
    FakeSession::default().page(&[], None)
}

fn connected(session: FakeSession) -> FakeConnector {
    FakeConnector::session(session, Generation::Modern)
}

/// Changes a seeded login before the run.
type Change = fn(&OAuthServer, &Harness);

/// The `Authorization` header of each connect, `none` when it had none.
fn bearers(h: &Harness) -> Vec<String> {
    h.connector
        .targets
        .lock()
        .unwrap()
        .iter()
        .map(|target| {
            target
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .map_or_else(|| "none".to_owned(), |(_, value)| value.clone())
        })
        .collect()
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn tools(h: &Harness) -> crate::support::Outcome {
    crate::support::auth::run_watched(h, &["tools", NAME], Act::Wait)
}

fn saved(h: &Harness) -> TokenRecord {
    stored(h.stores.keyring(), RecordKind::Tokens).unwrap()
}

#[test]
fn a_fresh_token_is_sent_as_is() {
    let (server, mut h) = logged_in(Script::default(), "");
    h.connector = connected(listing());
    assert_eq!(reply(&tools(&h)), json!([]));
    assert_eq!(bearers(&h), [bearer("at-0")]);
    assert!(server.paths().is_empty());
}

#[test]
fn a_token_within_a_minute_of_expiry_is_refreshed_first() {
    let expires = START + 3600;
    for (now, refreshed) in [
        (expires - 61, false),
        (expires - 60, true),
        (expires - 59, true),
        (expires + 10, true),
    ] {
        let (server, mut h) = logged_in(Script::default(), "");
        h.connector = connected(listing());
        h.clock.set(now);
        reply(&tools(&h));
        if !refreshed {
            assert_eq!(bearers(&h), [bearer("at-0")]);
            assert!(server.paths().is_empty());
            continue;
        }
        assert_eq!(bearers(&h), [bearer("at-1")], "{now}");
        let exchange = &server.to("/token")[0].params;
        assert_eq!(exchange["grant_type"], "refresh_token");
        assert_eq!(exchange["refresh_token"], "rt-0");
        assert_eq!(exchange["client_id"], "public-client");
        let renewed = saved(&h);
        assert_eq!(renewed.access_token, "at-1");
        assert_eq!(renewed.refresh_token.as_deref(), Some("rt-1"));
        assert_eq!(renewed.expires_at, Some(now + 3600));
    }
}

#[test]
fn a_refresh_without_a_new_refresh_token_keeps_the_old_one() {
    let (_server, mut h) = logged_in(
        Script {
            refresh_tokens: false,
            ..Script::default()
        },
        "",
    );
    h.connector = connected(listing());
    h.clock.set(START + 4000);
    reply(&tools(&h));
    assert_eq!(saved(&h).refresh_token.as_deref(), Some("rt-0"));
}

#[test]
fn a_401_gets_one_refresh_and_one_retry() {
    let (server, mut h) = logged_in(Script::default(), "");
    h.connector = FakeConnector::answer(Err(unauthorized(&server)))
        .then_session(listing(), Generation::Modern);
    reply(&tools(&h));
    assert_eq!(bearers(&h), [bearer("at-0"), bearer("at-1")]);
    assert_eq!(server.to("/token").len(), 1);
}

#[test]
fn a_second_401_asks_for_a_login() {
    let (server, mut h) = logged_in(Script::default(), "");
    h.connector =
        FakeConnector::answer(Err(unauthorized(&server))).then(Err(unauthorized(&server)));
    let (kind, message) = failure(&tools(&h));
    assert_eq!(kind, "auth_required");
    assert!(message.ends_with(HINT), "{message}");
    assert_eq!(server.to("/token").len(), 1);
}

#[test]
fn a_run_rejected_with_a_401_is_retried_with_the_new_token() {
    let (server, mut h) = logged_in(Script::default(), "");
    let session = FakeSession::default()
        .page(&[tool("t", &json!({"type": "object"}))], None)
        .call(Ok(ToolResult {
            value: json!({"content": []}),
            is_error: false,
        }));
    let log = session.log();
    h.connector =
        FakeConnector::answer(Err(unauthorized(&server))).then_session(session, Generation::Modern);
    let outcome = crate::support::auth::run_watched(&h, &["run", NAME, "t"], Act::Wait);
    assert_eq!(reply(&outcome), json!({"content": []}));
    assert_eq!(bearers(&h), [bearer("at-0"), bearer("at-1")]);
    assert_eq!(*log.lock().unwrap(), ["list ", "call t {}", "close"]);
}

#[test]
fn a_token_that_cannot_be_refreshed_asks_for_a_login() {
    let refused = Script {
        refuse_refresh: true,
        ..Script::default()
    };
    let cases: [(Script, Change, &str); 3] = [
        (refused, |_, _| {}, "refused"),
        (
            Script::default(),
            |server, h| {
                let mut kept = tokens(server);
                kept.refresh_token = None;
                seed(h.stores.keyring(), RecordKind::Tokens, &kept);
            },
            "the token expired and cannot be refreshed",
        ),
        (
            Script::default(),
            |server, h| {
                let mut other = client(server);
                other.client_id = "other-client".to_owned();
                seed(h.stores.keyring(), RecordKind::Registration, &other);
            },
            "the client the token was issued to is gone",
        ),
    ];
    for (script, change, expected) in cases {
        let (server, mut h) = logged_in(script, "");
        change(&server, &h);
        h.connector = connected(listing());
        h.clock.set(START + 4000);
        let (kind, message) = failure(&tools(&h));
        assert_eq!(kind, "auth_required");
        assert!(message.contains(expected), "{message}");
        assert!(message.ends_with(HINT), "{message}");
        assert_eq!(h.connector.connects(), 0);
    }
}

#[test]
fn a_missing_registration_is_gone_too() {
    let (_server, mut h) = logged_in(Script::default(), "");
    h.stores
        .keyring()
        .delete(&key(NAME, RecordKind::Registration))
        .unwrap();
    h.connector = connected(listing());
    h.clock.set(START + 4000);
    let (_kind, message) = failure(&tools(&h));
    assert!(message.contains("the client the token was issued to is gone"));
}

/// A file-backed login and the path of its token file.
fn file_login(server: &OAuthServer) -> (Harness, FileStore, std::path::PathBuf) {
    let h = harness(server, "credentials = \"file\"\n");
    let store = FileStore::new(h.home.path());
    store
        .set(
            &key(NAME, RecordKind::Tokens),
            &record::encode(&tokens(server)),
        )
        .unwrap();
    store
        .set(
            &key(NAME, RecordKind::Registration),
            &record::encode(&client(server)),
        )
        .unwrap();
    let path = store.path(&key(NAME, RecordKind::Tokens));
    (h, store, path)
}

#[test]
fn a_token_another_process_refreshed_is_used_without_refreshing() {
    let server = OAuthServer::start(Script::default());
    let (mut h, _store, path) = file_login(&server);
    let mut newer = tokens(&server);
    newer.access_token = "at-9".to_owned();
    let text = String::from_utf8(record::encode(&newer)).unwrap();
    h.connector = FakeConnector::answer(Err(unauthorized(&server)))
        .then_session(listing(), Generation::Modern)
        .rewriting(path, &text);
    reply(&tools(&h));
    assert_eq!(bearers(&h), [bearer("at-0"), bearer("at-9")]);
    assert!(server.paths().is_empty());
}

#[test]
fn a_login_removed_by_another_process_asks_for_a_new_one() {
    let server = OAuthServer::start(Script::default());
    let (mut h, _store, path) = file_login(&server);
    h.connector = FakeConnector::answer(Err(unauthorized(&server))).removing(path);
    let (kind, message) = failure(&tools(&h));
    assert_eq!(kind, "auth_required");
    assert_eq!(message, format!("the login was removed{HINT}"));
}

#[test]
fn a_403_for_more_scope_is_kept_for_the_next_login() {
    let long: Vec<String> = (0..MAX_PENDING_SCOPE_BYTES / 8)
        .map(|i| format!("s{i:07}"))
        .collect();
    let long = long.join(" ");
    let cases = [
        (Some("read write  admin write"), vec!["write", "admin"]),
        (None, vec![]),
        (Some(long.as_str()), vec![]),
    ];
    for (scope, pending) in cases {
        let (_server, mut h) = logged_in(Script::default(), "");
        h.connector = FakeConnector::answer(Err(needs_scope(scope)));
        let (kind, message) = failure(&tools(&h));
        assert_eq!(kind, "auth_required");
        assert!(message.ends_with(HINT), "{message}");
        assert_eq!(saved(&h).pending_scopes, pending);
    }
}

#[test]
fn a_403_after_the_login_was_removed_saves_nothing() {
    let server = OAuthServer::start(Script::default());
    let (mut h, store, path) = file_login(&server);
    h.connector = FakeConnector::answer(Err(needs_scope(Some("write")))).removing(path);
    assert_eq!(failure(&tools(&h)).0, "auth_required");
    assert!(store.get(&key(NAME, RecordKind::Tokens)).unwrap().is_none());
}

#[test]
fn a_token_is_used_only_for_its_server_and_client() {
    let other_resource = |server: &OAuthServer, h: &Harness| {
        let mut moved = tokens(server);
        moved.resource = "https://other.example/mcp".parse().unwrap();
        seed(h.stores.keyring(), RecordKind::Tokens, &moved);
    };
    let cases: [(&str, Change); 2] = [
        ("", other_resource),
        ("client_id = \"other-client\"\n", |_, _| {}),
    ];
    for (extra, change) in cases {
        let (server, mut h) = logged_in(Script::default(), extra);
        change(&server, &h);
        h.connector = connected(listing());
        let (kind, message) = failure(&tools(&h));
        assert_eq!(kind, "auth_required");
        assert!(
            message.contains("another server URL or client"),
            "{message}"
        );
        assert_eq!(h.connector.connects(), 0);
    }
}

#[test]
fn a_token_for_the_configured_client_is_used() {
    let (_server, mut h) = logged_in(Script::default(), "client_id = \"public-client\"\n");
    h.connector = connected(listing());
    reply(&tools(&h));
    assert_eq!(bearers(&h), [bearer("at-0")]);
}

#[test]
fn a_static_authorization_header_turns_the_login_off() {
    let (server, mut h) = logged_in(
        Script::default(),
        "headers = { authorization = \"Bearer static\" }\n",
    );
    h.connector = FakeConnector::answer(Err(unauthorized(&server)));
    let (kind, message) = failure(&tools(&h));
    assert_eq!(kind, "auth_required");
    assert!(message.ends_with(HINT), "{message}");
    assert_eq!(bearers(&h), [bearer("static")]);
}

#[test]
fn without_tokens_nothing_is_sent() {
    let server = OAuthServer::start(Script::default());
    for extra in ["", "credentials = \"keyring\"\n"] {
        let mut h = harness(&server, extra);
        h.connector = FakeConnector::answer(Err(unauthorized(&server)));
        let (kind, message) = failure(&tools(&h));
        assert_eq!(kind, "auth_required");
        assert!(message.ends_with(HINT), "{message}");
        assert_eq!(bearers(&h), ["none"]);
    }
    assert!(server.paths().is_empty());
}

#[test]
fn a_held_server_lock_times_out() {
    let limits = "[limits]\nrequest_timeout_secs = 1\nlock_wait_secs = 2\n";
    for scope_needed in [false, true] {
        let (server, mut h) = logged_in(Script::default(), limits);
        h.connector = if scope_needed {
            FakeConnector::answer(Err(needs_scope(Some("write"))))
        } else {
            h.clock.set(START + 4000);
            connected(listing())
        };
        let name = ServerName::parse(NAME).unwrap();
        let held = lock::server_lock(h.home.path(), &name, Duration::ZERO).unwrap();
        let failed = failure(&tools(&h));
        assert_eq!(failed.0, "credential_lock_timeout", "{}", failed.1);
        drop(held);
        assert!(server.paths().is_empty());
    }
}

#[test]
fn a_keyring_that_fails_fails_the_run() {
    for mode in [
        KeyringMode::Refuses(ErrorKind::CredentialStore),
        KeyringMode::Broken(ErrorKind::CredentialStore),
    ] {
        let (_server, mut h) = logged_in(Script::default(), "");
        h.stores.set_mode(mode);
        h.connector = connected(listing());
        assert_eq!(failure(&tools(&h)).0, "credential_store", "{mode:?}");
        assert_eq!(h.connector.connects(), 0);
    }
}

#[test]
fn a_record_corrupted_by_another_process_fails_the_run() {
    let server = OAuthServer::start(Script::default());
    for refusal in [unauthorized(&server), needs_scope(Some("write"))] {
        let (mut h, _store, path) = file_login(&server);
        h.connector = FakeConnector::answer(Err(refusal)).rewriting(path, "{}");
        assert_eq!(failure(&tools(&h)).0, "credential_invalid");
    }
    let (mut h, store, _path) = file_login(&server);
    fs::write(store.path(&key(NAME, RecordKind::Registration)), "{}").unwrap();
    h.clock.set(START + 4000);
    h.connector = connected(listing());
    assert_eq!(failure(&tools(&h)).0, "credential_invalid");
    assert!(server.paths().is_empty());
}

#[test]
fn a_refreshed_login_too_large_to_store_keeps_the_old_one() {
    let (server, mut h) = logged_in(
        Script {
            long_tokens: true,
            ..Script::default()
        },
        "",
    );
    h.clock.set(START + 4000);
    h.connector = connected(listing());
    assert_eq!(failure(&tools(&h)).0, "credential_too_large");
    assert_eq!(server.to("/token").len(), 1);
    assert_eq!(saved(&h).access_token, "at-0");
}

#[test]
fn a_client_secret_post_client_refreshes_with_its_secret_in_the_form() {
    let (server, mut h) = logged_in(Script::default(), "");
    let post = RegistrationRecord {
        client_secret: Some("s3cret".to_owned()),
        token_endpoint_auth_method: TokenEndpointAuth::ClientSecretPost,
        ..client(&server)
    };
    seed(h.stores.keyring(), RecordKind::Registration, &post);
    h.clock.set(START + 4000);
    h.connector = connected(listing());
    reply(&tools(&h));
    let exchange = &server.to("/token")[0];
    assert_eq!(exchange.params["client_id"], "public-client");
    assert_eq!(exchange.params["client_secret"], "s3cret");
    assert_eq!(exchange.authorization, None);
}

#[test]
fn a_403_for_another_reason_is_passed_on() {
    let (server, mut h) = logged_in(Script::default(), "");
    h.connector = FakeConnector::answer(Err(refusal(403, Some("forbidden"), None, None)));
    assert_eq!(failure(&tools(&h)).0, "auth_required");
    assert!(server.paths().is_empty());
    assert!(saved(&h).pending_scopes.is_empty());
}
