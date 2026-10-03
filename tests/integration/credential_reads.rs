//! Complete credential reads own the same lock as chunk writers.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use base64::{Engine, prelude::BASE64_STANDARD};
use mcpjump::config::limits::Limits;
use mcpjump::config::model::Generation;
use mcpjump::config::validate::ServerName;
use mcpjump::error::{Error, ErrorKind};
use mcpjump::store::file::FileStore;
use mcpjump::store::keyring::KeyringStore;
use mcpjump::store::record::{self, Record, TokenEndpointAuth, TokenRecord};
use mcpjump::store::select::{KeyringStart, StoreOpener};
use mcpjump::store::{CredentialStore, RecordKind, lock};
use tokio::time::Instant;

use crate::store_contract::key;
use crate::support::auth::{client, tokens, unauthorized};
use crate::support::fakes::browser::Behavior;
use crate::support::fakes::connector::{FakeConnector, FakeSession};
use crate::support::fakes::keyring::{FakeKeyring, Operation};
use crate::support::oauth_server::{OAuthServer, Script};
use crate::support::{Harness, Outcome};

const ENTRY_BYTES: usize = 2560;
const WATCHDOG: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct KeyringOpener(FakeKeyring);

impl StoreOpener for KeyringOpener {
    fn keyring(&self, limits: &Limits, deadline: Option<Instant>) -> Result<KeyringStart, Error> {
        Ok(KeyringStart::Ready(Box::new(KeyringStore::new(
            self.0.platform(),
            ENTRY_BYTES,
            Duration::from_secs(limits.keyring_timeout_secs),
            deadline,
        ))))
    }

    fn file(&self, config_dir: &Path) -> Box<dyn CredentialStore> {
        Box::new(FileStore::new(config_dir))
    }
}

fn store(fake: &FakeKeyring) -> KeyringStore {
    KeyringStore::new(fake.platform(), ENTRY_BYTES, WATCHDOG, None)
}

fn sized_tokens(server: &OAuthServer, size: usize, byte: char) -> TokenRecord {
    let mut record = tokens(server);
    record.access_token = byte.to_string();
    record.refresh_token = Some(byte.to_string());
    let padding = size.checked_sub(record::encode(&record).len()).unwrap();
    let access_padding = padding.min(16 * 1024 - 1);
    record.access_token = byte.to_string().repeat(access_padding + 1);
    record.refresh_token = Some(byte.to_string().repeat(padding - access_padding + 1));
    let encoded = record::encode(&record);
    assert_eq!(encoded.len(), size);
    assert!(record.is_valid());
    assert_eq!(
        record::decode::<TokenRecord>(&key("demo", RecordKind::Tokens), &encoded).unwrap(),
        record
    );
    record
}

fn command_worker(
    fake: FakeKeyring,
    dir: PathBuf,
    server: &OAuthServer,
    login: bool,
) -> (
    mpsc::Receiver<(Outcome, Vec<String>)>,
    thread::JoinHandle<()>,
) {
    let (sent, done) = mpsc::sync_channel(1);
    let resource = server.mcp_url();
    let refusal = unauthorized(server);
    let worker = thread::spawn(move || {
        let mut h = Harness::new();
        h.env = h.env.clone().with("MCPJUMP_HOME", dir.to_str().unwrap());
        let config = format!(
            "[servers.demo]\nurl = \"{resource}\"\ncredentials = \"keyring\"\ngeneration = \"modern\"\n"
        );
        std::fs::write(dir.join("config.toml"), config).unwrap();
        h.connector = if login {
            h.browser.set(Behavior::Follow);
            FakeConnector::answer(Err(refusal))
        } else {
            FakeConnector::session(FakeSession::default().page(&[], None), Generation::Modern)
        };
        let opener = KeyringOpener(fake);
        let deps = mcpjump::Deps {
            stores: &opener,
            ..h.deps()
        };
        let args = if login {
            vec!["mcpjump", "login", "demo"]
        } else {
            vec!["mcpjump", "tools", "demo"]
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = mcpjump::run(args, &deps, &mut out, &mut err);
        let headers = h
            .connector
            .targets
            .lock()
            .unwrap()
            .iter()
            .flat_map(|target| {
                target
                    .headers
                    .iter()
                    .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                    .map(|(_, value)| value.clone())
            })
            .collect();
        let _ = sent.send((
            Outcome {
                code,
                out: String::from_utf8(out).unwrap(),
                err: String::from_utf8(err).unwrap(),
            },
            headers,
        ));
    });
    (done, worker)
}

fn read_rejects_writer(
    old: &[u8],
    new: &[u8],
    kind: RecordKind,
    login: bool,
    server: &OAuthServer,
) {
    let fake = FakeKeyring::default();
    let store = store(&fake);
    let record_key = key("demo", kind);
    store.set(&record_key, old).unwrap();
    let before = fake.state().entries.clone();
    let mut gate = fake.gate(&record_key.account(), Operation::Get);
    let dir = tempfile::tempdir().unwrap();
    let (done, worker) = command_worker(fake.clone(), dir.path().to_owned(), server, login);
    gate.wait_reached();
    let name = ServerName::parse("demo").unwrap();
    let writer = lock::with_server_lock(dir.path(), &name, Duration::ZERO, None, &|| {
        store.set(&record_key, new)
    });
    let while_reading = fake.state().entries.clone();
    gate.release();
    gate.wait_completed();
    let (outcome, headers) = done.recv_timeout(WATCHDOG).unwrap();
    worker.join().unwrap();
    assert_eq!(writer.unwrap_err().kind(), ErrorKind::CredentialLockTimeout);
    assert_eq!(while_reading, before);
    assert_eq!(outcome.code, 0, "{}", outcome.err);
    if !login {
        let expected = record::decode::<TokenRecord>(&record_key, old).unwrap();
        assert_eq!(headers, [format!("Bearer {}", expected.access_token)]);
    }
    assert_eq!(store.get(&record_key).unwrap().unwrap(), old);
    lock::with_server_lock(dir.path(), &name, Duration::ZERO, None, &|| {
        store.set(&record_key, new)
    })
    .unwrap();
    assert_eq!(store.get(&record_key).unwrap().unwrap(), new);
}

#[test]
fn inline_and_chunked_token_reads_retain_the_complete_old_record() {
    let server = OAuthServer::start(Script::default());
    for size in [2560, 2561, 32000] {
        let old = record::encode(&sized_tokens(&server, size, 'a'));
        let new = record::encode(&sized_tokens(&server, size, 'b'));
        read_rejects_writer(&old, &new, RecordKind::Tokens, false, &server);
    }
    assert_eq!(server.paths(), Vec::<String>::new());
}

#[test]
fn a_login_registration_load_is_locked_until_its_chunks_are_decoded() {
    let server = OAuthServer::start(Script::default());
    let mut old = client(&server);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    old.redirect_uri = format!("http://127.0.0.1:{port}/callback").parse().unwrap();
    old.client_secret = Some("s".repeat(3000));
    old.token_endpoint_auth_method = TokenEndpointAuth::ClientSecretBasic;
    let mut new = old.clone();
    new.client_secret = Some("n".repeat(3000));
    assert!(old.is_valid());
    assert!(new.is_valid());
    read_rejects_writer(
        &record::encode(&old),
        &record::encode(&new),
        RecordKind::Registration,
        true,
        &server,
    );
    let authorize = server.to("/authorize");
    assert_eq!(authorize.len(), 1);
    assert_eq!(authorize[0].params["client_id"], "public-client");
    assert!(server.to("/register").is_empty());
    let expected = BASE64_STANDARD.encode(format!("public-client:{}", "s".repeat(3000)));
    assert_eq!(
        server.to("/token")[0].authorization.as_deref(),
        Some(format!("Basic {expected}").as_str())
    );
}
