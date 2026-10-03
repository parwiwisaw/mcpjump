//! `login` and `logout` in-process, against the OAuth fixture: the probe,
//! discovery, each way to register, the browser, a pasted redirect, and
//! the checks on the authorization response.

use std::net::TcpListener;
use std::time::Duration;

use mcpjump::config::model::Generation;
use mcpjump::error::{Error, ErrorKind};
use mcpjump::store::record::{
    RegistrationMethod, RegistrationRecord, TokenEndpointAuth, TokenRecord,
};
use mcpjump::store::{CredentialStore, RecordKind};
use serde_json::json;

use crate::support::Harness;
use crate::support::auth::{
    client, failure, harness, needs_scope, refusal, reply, run_watched, seed, stored, tokens,
    unauthorized,
};
use crate::support::fakes::browser::Behavior;
use crate::support::fakes::clock::START;
use crate::support::fakes::connector::{FakeConnector, FakeSession};
use crate::support::fakes::terminal::ScriptedTerminal;
use crate::support::fakes::user::Act;
use crate::support::oauth_server::{Doc, Iss, OAuthServer, Registration, Script};

/// A harness whose probe gets a 401 and whose browser follows the login.
fn ready(server: &OAuthServer, extra: &str) -> Harness {
    let mut h = harness(server, extra);
    h.connector = FakeConnector::answer(Err(unauthorized(server)));
    h.browser.set(Behavior::Follow);
    h
}

fn started(script: Script) -> OAuthServer {
    OAuthServer::start(script)
}

/// A loopback port nothing listens on.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn a_login_registers_authorizes_and_stores_the_tokens() {
    let server = started(Script::default());
    let h = ready(&server, "");
    let outcome = run_watched(&h, &["login", "demo"], Act::Wait);
    assert_eq!(
        reply(&outcome),
        json!({"server": "demo", "logged_in": true, "backend": "keyring", "scopes": ["read"]})
    );
    assert_eq!(
        server.paths(),
        ["/prm", "/metadata", "/register", "/authorize", "/token"]
    );
    let registered = &server.to("/register")[0].params;
    assert_eq!(registered["token_endpoint_auth_method"], "none");
    assert_eq!(registered["application_type"], "native");
    let authorize = &server.to("/authorize")[0].params;
    assert_eq!(authorize["client_id"], "public-client");
    assert_eq!(authorize["redirect_uri"], registered["redirect_uri"]);
    assert_eq!(authorize["response_type"], "code");
    assert_eq!(authorize["code_challenge_method"], "S256");
    assert_eq!(authorize["resource"], server.mcp_url().as_str());
    assert_eq!(authorize["scope"], "read");
    let exchange = &server.to("/token")[0];
    assert_eq!(exchange.params["grant_type"], "authorization_code");
    assert_eq!(exchange.params["client_id"], "public-client");
    assert_eq!(exchange.params["resource"], server.mcp_url().as_str());
    assert_eq!(exchange.authorization, None);
    let saved: TokenRecord = stored(h.stores.keyring(), RecordKind::Tokens).unwrap();
    assert_eq!(saved.access_token, "at-1");
    assert_eq!(saved.refresh_token.as_deref(), Some("rt-1"));
    assert_eq!(saved.expires_at, Some(START + 3600));
    assert_eq!(saved.issuer, server.base);
    let registration: RegistrationRecord =
        stored(h.stores.keyring(), RecordKind::Registration).unwrap();
    assert_eq!(registration.method, RegistrationMethod::Dynamic);
    assert!(h.config_text().contains("credentials = \"keyring\""));
    let opened = h.browser.opened.lock().unwrap().clone();
    assert_eq!(opened[0].0.as_str(), authorize_url(&outcome.err));
    assert_eq!(opened[0].1, Duration::from_secs(5));
}

/// The URL of the authorize notice on stderr.
fn authorize_url(err: &str) -> String {
    let notice: serde_json::Value = serde_json::from_str(err.lines().next().unwrap()).unwrap();
    notice["authorize"]["url"].as_str().unwrap().to_owned()
}

#[test]
fn a_second_login_reuses_the_registration_and_keeps_the_scopes() {
    let server = started(Script::default());
    let mut h = ready(&server, "");
    h.connector =
        FakeConnector::answer(Err(unauthorized(&server))).then(Err(needs_scope(Some("write"))));
    reply(&run_watched(&h, &["login", "demo"], Act::Wait));
    let mut saved: TokenRecord = stored(h.stores.keyring(), RecordKind::Tokens).unwrap();
    saved.pending_scopes = vec!["admin".to_owned()];
    seed(h.stores.keyring(), RecordKind::Tokens, &saved);
    reply(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert_eq!(server.to("/register").len(), 1);
    assert_eq!(
        server.to("/authorize")[1].params["scope"],
        "write read admin"
    );
    let renewed: TokenRecord = stored(h.stores.keyring(), RecordKind::Tokens).unwrap();
    assert_eq!(renewed.pending_scopes, Vec::<String>::new());
}

#[test]
fn a_server_that_wants_a_secret_gets_a_basic_client() {
    let server = started(Script {
        registration: Registration::SecretOnly,
        ..Script::default()
    });
    let h = ready(&server, "");
    reply(&run_watched(&h, &["login", "demo"], Act::Wait));
    let methods: Vec<String> = server
        .to("/register")
        .iter()
        .map(|request| request.params["token_endpoint_auth_method"].clone())
        .collect();
    assert_eq!(methods, ["none", "client_secret_basic"]);
    let exchange = &server.to("/token")[0];
    assert!(
        exchange
            .authorization
            .as_deref()
            .unwrap()
            .starts_with("Basic ")
    );
    assert!(!exchange.params.contains_key("client_id"));
    let registration: RegistrationRecord =
        stored(h.stores.keyring(), RecordKind::Registration).unwrap();
    assert_eq!(
        registration.token_endpoint_auth_method,
        TokenEndpointAuth::ClientSecretBasic
    );
    assert_eq!(registration.client_secret.as_deref(), Some("s3cret"));
}

#[test]
fn a_server_that_cannot_register_mcpjump_asks_for_a_client_id() {
    for (registration, expected) in [
        (Registration::Refuse, "\"invalid_redirect_uri\""),
        (Registration::Absent, "--client-id"),
    ] {
        let server = started(Script {
            registration,
            ..Script::default()
        });
        let h = ready(&server, "");
        let (kind, message) = failure(&run_watched(&h, &["login", "demo"], Act::Wait));
        assert_eq!(kind, "auth_required");
        assert!(message.contains(expected), "{message}");
        assert!(!server.paths().contains(&"/authorize".to_owned()));
    }
}

#[test]
fn a_preregistered_client_is_used_without_registering() {
    let server = started(Script::default());
    let port = free_port();
    let h = ready(
        &server,
        &format!("client_id = \"pre-client\"\ncallback_port = {port}\n"),
    );
    reply(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert!(server.to("/register").is_empty());
    let authorize = &server.to("/authorize")[0].params;
    assert_eq!(authorize["client_id"], "pre-client");
    assert_eq!(
        authorize["redirect_uri"],
        format!("http://127.0.0.1:{port}/callback")
    );
    let registration: RegistrationRecord =
        stored(h.stores.keyring(), RecordKind::Registration).unwrap();
    assert_eq!(registration.method, RegistrationMethod::Preregistered);
}

#[test]
fn a_preregistered_client_is_not_moved_to_another_issuer() {
    let server = started(Script::default());
    let h = ready(
        &server,
        "client_id = \"pre-client\"\ncredentials = \"keyring\"\n",
    );
    let mut moved = client(&server);
    moved.client_id = "pre-client".to_owned();
    moved.method = RegistrationMethod::Preregistered;
    moved.issuer = "https://other.example/".parse().unwrap();
    seed(h.stores.keyring(), RecordKind::Registration, &moved);
    let (kind, message) = failure(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert_eq!(kind, "auth_required");
    assert!(
        message.contains("another authorization server"),
        "{message}"
    );
}

#[test]
fn a_saved_registration_of_another_client_does_not_block_a_preregistered_one() {
    let server = started(Script::default());
    let mut other = client(&server);
    other.client_id = "other-client".to_owned();
    other.method = RegistrationMethod::Preregistered;
    other.issuer = "https://other.example/".parse().unwrap();
    for saved in [client(&server), other] {
        let h = ready(
            &server,
            "client_id = \"pre-client\"\ncredentials = \"keyring\"\n",
        );
        seed(h.stores.keyring(), RecordKind::Registration, &saved);
        reply(&run_watched(&h, &["login", "demo"], Act::Wait));
        let registration: RegistrationRecord =
            stored(h.stores.keyring(), RecordKind::Registration).unwrap();
        assert_eq!(registration.client_id, "pre-client");
    }
}

#[test]
fn a_saved_preregistered_client_is_not_reused_without_its_client_id() {
    let server = started(Script::default());
    let h = ready(&server, "credentials = \"keyring\"\n");
    let mut saved = client(&server);
    saved.client_id = "pre-client".to_owned();
    saved.method = RegistrationMethod::Preregistered;
    saved.redirect_uri = format!("http://127.0.0.1:{}/callback", free_port())
        .parse()
        .unwrap();
    seed(h.stores.keyring(), RecordKind::Registration, &saved);
    reply(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert_eq!(server.to("/register").len(), 1);
    assert_eq!(
        server.to("/authorize")[0].params["client_id"],
        "public-client"
    );
}

#[test]
fn a_registration_answered_with_200_is_accepted() {
    let server = started(Script {
        registration: Registration::PublicOk,
        ..Script::default()
    });
    let h = ready(&server, "");
    assert_eq!(
        reply(&run_watched(&h, &["login", "demo"], Act::Wait))["logged_in"],
        true
    );
}

#[test]
fn a_login_requests_at_most_64_scopes_and_only_its_own_kept_ones() {
    let server = started(Script {
        resource_doc: Doc::Patched(|d| {
            d["scopes_supported"] = json!((0..64).map(|i| format!("s{i}")).collect::<Vec<_>>());
        }),
        ..Script::default()
    });
    let h = ready(&server, "credentials = \"keyring\"\n");
    let mut kept = tokens(&server);
    kept.pending_scopes = vec!["extra".to_owned()];
    seed(h.stores.keyring(), RecordKind::Tokens, &kept);
    reply(&run_watched(&h, &["login", "demo"], Act::Wait));
    let first = server.to("/authorize")[0].params["scope"].clone();
    assert_eq!(first.split(' ').count(), 64);
    assert!(!first.contains("extra"), "{first}");
    let other = started(Script::default());
    let h = ready(&other, "credentials = \"keyring\"\n");
    let mut elsewhere = tokens(&other);
    elsewhere.resource = "http://127.0.0.1:1/mcp".parse().unwrap();
    elsewhere.pending_scopes = vec!["admin".to_owned()];
    seed(h.stores.keyring(), RecordKind::Tokens, &elsewhere);
    reply(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert_eq!(other.to("/authorize")[0].params["scope"], "read");
}

#[test]
fn a_client_metadata_document_names_the_client_and_its_port() {
    let port = free_port();
    let server = started(Script {
        cimd: true,
        redirect_uris: vec![
            "not a url".to_owned(),
            "http://localhost:1/callback".to_owned(),
            format!("http://127.0.0.1:{port}/callback"),
        ],
        ..Script::default()
    });
    let document = server.base.join("client.json").unwrap();
    let h = ready(
        &server,
        &format!("[settings]\nclient_metadata_url = \"{document}\"\n"),
    );
    reply(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert!(server.to("/register").is_empty());
    let authorize = &server.to("/authorize")[0].params;
    assert_eq!(authorize["client_id"], document.as_str());
    assert_eq!(
        authorize["redirect_uri"],
        format!("http://127.0.0.1:{port}/callback")
    );
}

#[test]
fn a_client_metadata_document_must_be_usable() {
    let busy = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap().port();
    let cases = [
        (
            Some("https://other.example/client.json"),
            "client.json",
            "protocol_error",
        ),
        (None, "missing.json", "http_status"),
        (None, "client.json", "auth_required"),
    ];
    for (client_id, path, expected) in cases {
        let server = started(Script {
            cimd: true,
            redirect_uris: vec![format!("http://127.0.0.1:{port}/callback")],
            document_client_id: client_id.map(str::to_owned),
            ..Script::default()
        });
        let document = server.base.join(path).unwrap();
        let h = ready(
            &server,
            &format!("[settings]\nclient_metadata_url = \"{document}\"\n"),
        );
        let (kind, _message) = failure(&run_watched(&h, &["login", "demo"], Act::Wait));
        assert_eq!(kind, expected, "{path}");
    }
    drop(busy);
}

#[test]
fn the_user_can_paste_the_redirect_from_another_machine() {
    let server = started(Script::default());
    let mut h = ready(&server, "");
    let (terminal, lines) = ScriptedTerminal::piped(4);
    lines.try_send("garbage".to_owned()).unwrap();
    h.terminal = terminal;
    let outcome = run_watched(&h, &["login", "demo", "--no-browser"], Act::Paste(lines));
    assert_eq!(reply(&outcome)["logged_in"], true);
    assert!(
        outcome
            .err
            .contains("ignored the pasted URL: it is not a URL"),
        "{}",
        outcome.err
    );
    assert_eq!(h.browser.opens(), 0);
}

#[test]
fn too_many_bad_pastes_end_the_login() {
    let server = started(Script::default());
    let mut h = ready(&server, "");
    h.terminal = ScriptedTerminal::pasting(&["garbage"; 17]);
    let outcome = run_watched(&h, &["login", "demo", "--no-browser"], Act::Wait);
    let (kind, message) = failure(&outcome);
    assert_eq!(kind, "auth_required");
    assert!(
        message.contains("too many invalid pasted URLs"),
        "{message}"
    );
}

#[test]
fn a_login_nothing_can_answer_any_more_ends() {
    let server = started(Script::default());
    let mut h = ready(&server, "");
    h.terminal = ScriptedTerminal::pasting(&[]);
    let outcome = run_watched(&h, &["login", "demo", "--no-browser"], Act::Hangup);
    let (kind, _) = failure(&outcome);
    assert_eq!(kind, "login_timeout");
    assert!(server.to("/token").is_empty());
}

#[test]
fn a_browser_that_does_not_open_is_a_warning() {
    let server = started(Script::default());
    let h = ready(&server, "");
    h.browser.set(Behavior::Fail("no display".to_owned()));
    let outcome = run_watched(&h, &["login", "demo"], Act::Open);
    assert_eq!(reply(&outcome)["logged_in"], true);
    assert!(
        outcome.err.contains("could not open a browser: no display"),
        "{}",
        outcome.err
    );
}

#[test]
fn a_refused_login_is_auth_required() {
    let server = started(Script {
        deny: true,
        ..Script::default()
    });
    let h = ready(&server, "");
    let (kind, message) = failure(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert_eq!(kind, "auth_required");
    assert!(message.contains("\"access_denied\""), "{message}");
    assert!(server.to("/token").is_empty());
}

#[test]
fn the_authorization_response_must_name_its_issuer_when_advertised() {
    for (iss, expected) in [
        (Iss::Wrong, Some("protocol_error")),
        (Iss::Omitted, Some("protocol_error")),
        (Iss::Unadvertised, None),
    ] {
        let server = started(Script {
            iss,
            ..Script::default()
        });
        let h = ready(&server, "");
        let outcome = run_watched(&h, &["login", "demo"], Act::Wait);
        match expected {
            Some(kind) => {
                assert_eq!(failure(&outcome).0, kind);
                assert!(server.to("/token").is_empty());
            }
            None => assert_eq!(reply(&outcome)["logged_in"], true),
        }
    }
}

#[test]
fn corrupt_stored_records_are_replaced() {
    let server = started(Script::default());
    let h = ready(&server, "credentials = \"keyring\"\n");
    for kind in RecordKind::ALL {
        h.stores
            .keyring()
            .set(&crate::store_contract::key("demo", kind), b"{}")
            .unwrap();
    }
    reply(&run_watched(&h, &["login", "demo"], Act::Wait));
    let saved: TokenRecord = stored(h.stores.keyring(), RecordKind::Tokens).unwrap();
    assert_eq!(saved.access_token, "at-1");
}

#[test]
fn a_server_that_answers_without_a_login_needs_none() {
    let server = started(Script::default());
    let mut h = harness(&server, "");
    let session = FakeSession::default().page(&[], None);
    let log = session.log();
    h.connector = FakeConnector::session(session, Generation::Modern);
    let outcome = run_watched(&h, &["login", "demo"], Act::Wait);
    assert_eq!(
        reply(&outcome),
        json!({"server": "demo", "logged_in": false, "auth_required": false})
    );
    assert_eq!(*log.lock().unwrap(), ["list ", "close"]);
    assert!(server.paths().is_empty());
}

#[test]
fn a_challenge_from_the_tools_list_starts_the_login() {
    let server = started(Script::default());
    let mut h = ready(&server, "");
    let session = FakeSession::default().page_error(needs_scope(Some("write")));
    h.connector = FakeConnector::session(session, Generation::Modern);
    reply(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert_eq!(server.to("/authorize")[0].params["scope"], "write");
}

#[test]
fn a_probe_failure_without_a_login_challenge_is_returned() {
    let server = started(Script::default());
    for refused in [
        Error::new(ErrorKind::Network, "down"),
        refusal(403, None, None, None),
    ] {
        let mut h = harness(&server, "");
        let kind = refused.kind().as_str();
        h.connector = FakeConnector::answer(Err(refused));
        assert_eq!(
            failure(&run_watched(&h, &["login", "demo"], Act::Wait)).0,
            kind
        );
    }
    assert!(server.paths().is_empty());
}

#[test]
fn a_server_with_a_static_authorization_header_is_not_logged_in() {
    let server = started(Script::default());
    let h = harness(&server, "headers = { authorization = \"Bearer x\" }\n");
    let (kind, message) = failure(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert_eq!(kind, "usage");
    assert!(message.contains("static Authorization header"), "{message}");
}

#[test]
fn logout_deletes_the_tokens_and_keeps_the_registration() {
    let server = started(Script::default());
    let h = harness(&server, "credentials = \"keyring\"\n");
    seed(h.stores.keyring(), RecordKind::Tokens, &tokens(&server));
    seed(
        h.stores.keyring(),
        RecordKind::Registration,
        &client(&server),
    );
    assert_eq!(
        h.run(&["logout", "demo"]).json(),
        json!({"server": "demo", "logged_out": true})
    );
    assert!(stored::<TokenRecord>(h.stores.keyring(), RecordKind::Tokens).is_none());
    assert!(stored::<RegistrationRecord>(h.stores.keyring(), RecordKind::Registration).is_some());
}

#[test]
fn logout_without_a_login_changes_nothing() {
    let server = started(Script::default());
    let h = harness(&server, "");
    assert_eq!(
        h.run(&["logout", "demo"]).json(),
        json!({"server": "demo", "logged_out": false})
    );
    assert_eq!(h.run(&["logout", "nope"]).error_kind(), "unknown_server");
}
