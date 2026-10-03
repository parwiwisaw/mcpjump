//! One absolute command budget covers authentication and all lock waits.

use std::path::Path;
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::Duration;

use mcpjump::config::model::Generation;
use mcpjump::config::validate::ServerName;
use mcpjump::error::{Error, ErrorKind};
use mcpjump::files::FileLock;
use mcpjump::mcp::connector::{Connection, SessionConnector, Target};
use mcpjump::mcp::session::{BoxFuture, ToolResult};
use mcpjump::store::{RecordKind, lock};
use serde_json::json;

use crate::support::auth::{client, seed, tokens, unauthorized};
use crate::support::fakes::connector::{FakeConnector, FakeSession, tool};
use crate::support::oauth_server::{OAuthServer, Script};
use crate::support::{Harness, Outcome};

fn token_timeout(command_secs: u64, auth_secs: u64, expected: ErrorKind) {
    let server = OAuthServer::start(Script::default());
    server.expect_refresh("rt-0");
    let gate = server.gate_tokens();
    let record = tokens(&server);
    let client = client(&server);
    let (sent, done) = mpsc::sync_channel(1);
    let started = std::time::Instant::now();
    let worker = thread::spawn(move || {
        let h = Harness::new();
        h.write_config(&format!(
            "[servers.demo]\nurl = \"{}\"\ncredentials = \"keyring\"\n\
             [limits]\nrequest_timeout_secs = 5\nlock_wait_secs = 6\nauth_network_budget_secs = {auth_secs}\n",
            record.resource
        ));
        seed(h.stores.keyring(), RecordKind::Tokens, &record);
        seed(h.stores.keyring(), RecordKind::Registration, &client);
        h.clock.set(crate::support::fakes::clock::START + 4000);
        let command_secs = command_secs.to_string();
        let outcome = h.run(&["run", "demo", "t", "--timeout", &command_secs]);
        let _ = sent.send((outcome, h.connector.connects(), h.browser.opens()));
    });
    gate.wait_reached();
    let result = done.recv_timeout(Duration::from_secs(5));
    drop(gate);
    if result.is_err() {
        let _ = done.recv_timeout(Duration::from_secs(5));
    }
    worker.join().unwrap();
    let (outcome, connects, browsers) = result.unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(outcome.code, expected.exit_code(), "{}", outcome.err);
    assert!(outcome.out.is_empty());
    assert_eq!(outcome.error_kind(), expected.as_str());
    assert_eq!(connects, 0);
    assert_eq!(browsers, 0);
    assert_eq!(server.to("/token").len(), 1);
    assert!(server.to("/mcp").is_empty());
}

#[test]
fn stalled_token_exchange_obeys_run_timeout_and_preserves_an_earlier_auth_limit() {
    token_timeout(1, 5, ErrorKind::RequestTimeout);
    token_timeout(3, 1, ErrorKind::AuthTimeout);
}

#[test]
fn a_held_credential_lock_is_clipped_to_the_command_budget() {
    for (timeout, expected) in [
        (1, ErrorKind::RequestTimeout),
        (4, ErrorKind::CredentialLockTimeout),
    ] {
        let server = OAuthServer::start(Script::default());
        let h = Harness::new();
        h.write_config(&format!(
            "[servers.demo]\nurl = \"{}\"\ncredentials = \"keyring\"\n\
             [limits]\nrequest_timeout_secs = 1\nlock_wait_secs = 2\n",
            server.mcp_url()
        ));
        seed(h.stores.keyring(), RecordKind::Tokens, &tokens(&server));
        let name = ServerName::parse("demo").unwrap();
        let held = lock::server_lock(h.home.path(), &name, Duration::ZERO, None).unwrap();
        let started = std::time::Instant::now();
        let outcome = h.run(&["run", "demo", "t", "--timeout", &timeout.to_string()]);
        drop(held);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(outcome.code, expected.exit_code());
        assert_eq!(outcome.error_kind(), expected.as_str());
        assert_eq!(h.connector.connects(), 0);
        assert!(server.paths().is_empty());
    }
}

#[derive(Debug)]
struct SaveLockConnector<'a> {
    inner: &'a FakeConnector,
    dir: &'a Path,
    held: Mutex<Option<FileLock>>,
}

impl SessionConnector for SaveLockConnector<'_> {
    fn connect(&self, target: Target) -> BoxFuture<'_, Result<Connection, Error>> {
        *self.held.lock().unwrap() = Some(
            mcpjump::files::lock(&self.dir.join("locks/config.lock"), Duration::ZERO).unwrap(),
        );
        self.inner.connect(target)
    }
}

#[test]
fn generation_save_contention_after_config_load_cannot_extend_run_timeout() {
    let mut h = Harness::new();
    let original = "[servers.demo]\nurl = \"https://example.com/mcp\"\n\
                    [limits]\nrequest_timeout_secs = 1\nlock_wait_secs = 2\n";
    h.write_config(original);
    let session = FakeSession::default()
        .page(&[tool("t", &json!({}))], None)
        .call(Ok(ToolResult {
            value: json!({"content":[]}),
            is_error: false,
        }));
    let log = session.log();
    h.connector = FakeConnector::session(session, Generation::Modern);
    let connector = SaveLockConnector {
        inner: &h.connector,
        dir: h.home.path(),
        held: Mutex::new(None),
    };
    let deps = mcpjump::Deps {
        connector: &connector,
        ..h.deps()
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let started = std::time::Instant::now();
    let code = mcpjump::run(
        ["mcpjump", "run", "demo", "t", "--timeout", "1"],
        &deps,
        &mut out,
        &mut err,
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(code, 4);
    let outcome = Outcome {
        code,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    };
    assert_eq!(outcome.error_kind(), "request_timeout");
    assert_eq!(h.connector.connects(), 1);
    assert_eq!(*log.lock().unwrap(), ["close"]);
    assert_eq!(h.config_text(), original);
}

#[derive(Debug)]
struct NearBudgetConnector<'a> {
    inner: &'a FakeConnector,
    delay: Duration,
    attempts: Mutex<usize>,
}

impl SessionConnector for NearBudgetConnector<'_> {
    fn connect(&self, target: Target) -> BoxFuture<'_, Result<Connection, Error>> {
        let first = {
            let mut attempts = self.attempts.lock().unwrap();
            *attempts += 1;
            *attempts == 1
        };
        // Record readiness before the timer consumes the absolute budget.
        let answer = self.inner.connect(target);
        Box::pin(async move {
            if first {
                tokio::time::sleep(self.delay).await;
            }
            answer.await
        })
    }
}

fn retry_budget(delay: Duration, succeeds: bool) {
    let server = OAuthServer::start(Script::default());
    server.expect_refresh("rt-0");
    let mut h = Harness::new();
    h.write_config(&format!("[servers.demo]\nurl = \"{}\"\ncredentials = \"keyring\"\ngeneration = \"modern\"\n[limits]\nrequest_timeout_secs = 1\nlock_wait_secs = 2\n", server.mcp_url()));
    seed(h.stores.keyring(), RecordKind::Tokens, &tokens(&server));
    seed(
        h.stores.keyring(),
        RecordKind::Registration,
        &client(&server),
    );
    h.connector = FakeConnector::answer(Err(unauthorized(&server)))
        .then_session(FakeSession::default().page(&[], None), Generation::Modern);
    let connector = NearBudgetConnector {
        inner: &h.connector,
        delay,
        attempts: Mutex::new(0),
    };
    let deps = mcpjump::Deps {
        connector: &connector,
        ..h.deps()
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = mcpjump::run(["mcpjump", "tools", "demo"], &deps, &mut out, &mut err);
    let targets = h.connector.targets.lock().unwrap();
    if succeeds {
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].deadline, targets[1].deadline);
        assert_eq!(server.to("/token").len(), 1);
    } else {
        assert_eq!(code, 4);
        assert!(out.is_empty());
        assert_eq!(targets.len(), 1);
        assert!(server.paths().is_empty());
    }
}

#[test]
fn a_near_budget_401_refresh_reuses_the_exact_original_deadline() {
    retry_budget(Duration::from_millis(3250), true);
    retry_budget(Duration::from_millis(4050), false);
}

#[test]
fn an_expired_connected_session_closes_before_listing() {
    let mut h = Harness::new();
    h.write_config("[servers.demo]\nurl = \"https://example.com/mcp\"\ngeneration = \"modern\"\n[limits]\nrequest_timeout_secs = 1\n");
    let session = FakeSession::default();
    let log = session.log();
    h.connector = FakeConnector::session(session, Generation::Modern);
    let connector = NearBudgetConnector {
        inner: &h.connector,
        delay: Duration::from_millis(4050),
        attempts: Mutex::new(0),
    };
    let deps = mcpjump::Deps {
        connector: &connector,
        ..h.deps()
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let started = std::time::Instant::now();
    let code = mcpjump::run(["mcpjump", "tools", "demo"], &deps, &mut out, &mut err);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(code, ErrorKind::RequestTimeout.exit_code());
    assert!(out.is_empty());
    let outcome = Outcome {
        code,
        out: String::new(),
        err: String::from_utf8(err).unwrap(),
    };
    assert_eq!(outcome.error_kind(), "request_timeout");
    assert_eq!(h.connector.connects(), 1);
    assert_eq!(*log.lock().unwrap(), ["close"]);
}

#[test]
fn expired_server_lock_requests_create_no_artifacts_or_work() {
    let dir = tempfile::tempdir().unwrap();
    let name = ServerName::parse("demo").unwrap();
    let expired = tokio::time::Instant::now() - Duration::from_secs(1);
    assert_eq!(
        lock::server_lock(dir.path(), &name, Duration::from_secs(3), Some(expired))
            .unwrap_err()
            .kind(),
        ErrorKind::RequestTimeout
    );
    let called = std::cell::Cell::new(false);
    let result = lock::with_server_lock(
        dir.path(),
        &name,
        Duration::from_secs(3),
        Some(expired),
        &|| {
            called.set(true);
            Ok(())
        },
    );
    assert_eq!(result.unwrap_err().kind(), ErrorKind::RequestTimeout);
    assert!(!called.get());
    assert!(!dir.path().join("locks").exists());
}
