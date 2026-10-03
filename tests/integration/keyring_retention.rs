//! An abandoned fake credential writer retains its server lock until exit.

use std::io::{BufRead, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use mcpjump::config::validate::ServerName;
use mcpjump::error::ErrorKind;
use mcpjump::store::keyring::KeyringStore;
use mcpjump::store::record::{self, Record, TokenRecord};
use mcpjump::store::{CredentialStore, RecordKind, lock};

use crate::store_contract::key;
use crate::support::fakes::keyring::{FakeKeyring, Operation};

const MARKER: &str = "mcpjump.fake-keyring-retention.v1";
const IO_CAP: u64 = 16 * 1024;
const WATCHDOG: Duration = Duration::from_secs(5);

fn token(byte: char) -> TokenRecord {
    let record = TokenRecord {
        access_token: byte.to_string().repeat(3000),
        refresh_token: Some("refresh".to_owned()),
        expires_at: None,
        token_type: "Bearer".to_owned(),
        scopes: vec!["read".to_owned()],
        issuer: "https://issuer.example/".parse().unwrap(),
        resource: "https://resource.example/mcp".parse().unwrap(),
        client_id: "client".to_owned(),
        token_endpoint: "https://issuer.example/token".parse().unwrap(),
        pending_scopes: vec![],
    };
    assert!(record.is_valid());
    record
}

fn output(line: &str) {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "RETENTION {line}").unwrap();
    stdout.flush().unwrap();
}

fn instructions() -> mpsc::Receiver<String> {
    let (sent, received) = mpsc::sync_channel(2);
    thread::spawn(move || {
        let mut input = std::io::BufReader::new(std::io::stdin().take(1024));
        for _ in 0..2 {
            let mut line = String::new();
            if input.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if sent.send(line.trim().to_owned()).is_err() {
                break;
            }
        }
    });
    received
}

fn write_worker(
    fake: FakeKeyring,
    dir: std::path::PathBuf,
    new_bytes: Vec<u8>,
    command: bool,
) -> (
    mpsc::Receiver<Result<(), mcpjump::error::Error>>,
    thread::JoinHandle<()>,
) {
    let (sent, done) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let own = if command {
            Duration::from_secs(3)
        } else {
            Duration::from_millis(250)
        };
        let cap = if command {
            Duration::from_millis(250)
        } else {
            Duration::from_secs(3)
        };
        let store = KeyringStore::new(
            fake.platform(),
            2560,
            own,
            Some(tokio::time::Instant::now() + cap),
        );
        let name = ServerName::parse("demo").unwrap();
        let result = lock::with_server_lock(&dir, &name, Duration::ZERO, None, &|| {
            store.set(&key("demo", RecordKind::Tokens), &new_bytes)
        });
        let _ = sent.send(result);
    });
    (done, worker)
}

#[test]
fn late_write_probe() {
    if std::env::var("MCPJUMP_FAKE_RETENTION_PROBE").as_deref() != Ok(MARKER) {
        return;
    }
    let dir = std::path::PathBuf::from(std::env::var_os("MCPJUMP_FAKE_RETENTION_DIR").unwrap());
    let command = std::env::var("MCPJUMP_FAKE_RETENTION_CAUSE").unwrap() == "command";
    let fake = FakeKeyring::default();
    let ordinary = KeyringStore::new(fake.platform(), 2560, WATCHDOG, None);
    let account = key("demo", RecordKind::Tokens);
    let old = token('o');
    let new = token('n');
    ordinary.set(&account, &record::encode(&old)).unwrap();
    let mut gate = fake.gate(&account.account(), Operation::Set);
    let (done, worker) = write_worker(fake.clone(), dir, record::encode(&new), command);
    gate.wait_reached();
    let result = done.recv_timeout(WATCHDOG).unwrap();
    worker.join().unwrap();
    assert_eq!(
        result.unwrap_err().kind(),
        if command {
            ErrorKind::RequestTimeout
        } else {
            ErrorKind::KeyringTimeout
        }
    );
    let read = ordinary.get(&account).unwrap().unwrap();
    assert_eq!(record::decode::<TokenRecord>(&account, &read).unwrap(), old);
    output("timeout-old-record");
    let commands = instructions();
    assert_eq!(commands.recv_timeout(WATCHDOG).unwrap(), "release");
    let mut tail = fake.gate("demo/tokens@0#1", Operation::Delete);
    gate.release();
    gate.wait_completed();
    tail.wait_reached();
    tail.release();
    tail.wait_completed();
    let read = ordinary.get(&account).unwrap().unwrap();
    assert_eq!(record::decode::<TokenRecord>(&account, &read).unwrap(), new);
    output("completed-new-record");
    assert_eq!(commands.recv_timeout(WATCHDOG).unwrap(), "exit");
}

struct Probe {
    child: Child,
    markers: mpsc::Receiver<String>,
    stdout: Option<Capture>,
    stderr: Option<Capture>,
}

struct Capture {
    done: mpsc::Receiver<Vec<u8>>,
    worker: thread::JoinHandle<()>,
}

fn capture(
    mut source: impl Read + Send + 'static,
    sent: Option<mpsc::SyncSender<String>>,
) -> Capture {
    let (completed, done) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(sent) = sent {
            let mut lines = std::io::BufReader::new(source.take(IO_CAP + 1));
            loop {
                let mut line = String::new();
                if lines.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                bytes.extend_from_slice(line.as_bytes());
                if let Some(marker) = line.strip_prefix("RETENTION ") {
                    let _ = sent.try_send(marker.trim().to_owned());
                }
            }
        } else {
            source
                .by_ref()
                .take(IO_CAP + 1)
                .read_to_end(&mut bytes)
                .unwrap();
        }
        assert!(u64::try_from(bytes.len()).unwrap() <= IO_CAP);
        let _ = completed.send(bytes);
    });
    Capture { done, worker }
}

impl Capture {
    fn finish(self) {
        let complete = self.done.recv_timeout(WATCHDOG);
        let joined = self.worker.join();
        assert!(complete.is_ok() || thread::panicking());
        assert!(joined.is_ok() || thread::panicking());
    }
}

impl Probe {
    fn spawn(dir: &std::path::Path, cause: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "keyring_retention::late_write_probe",
                "--nocapture",
            ])
            .env("MCPJUMP_FAKE_RETENTION_PROBE", MARKER)
            .env("MCPJUMP_FAKE_RETENTION_DIR", dir)
            .env("MCPJUMP_FAKE_RETENTION_CAUSE", cause)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (sent, markers) = mpsc::sync_channel(2);
        let stdout = capture(child.stdout.take().unwrap(), Some(sent));
        let stderr = capture(child.stderr.take().unwrap(), None);
        Self {
            child,
            markers,
            stdout: Some(stdout),
            stderr: Some(stderr),
        }
    }

    fn say(&mut self, message: &str) {
        let input = self.child.stdin.as_mut().unwrap();
        writeln!(input, "{message}").unwrap();
        input.flush().unwrap();
    }

    fn marker(&self, expected: &str) {
        assert_eq!(self.markers.recv_timeout(WATCHDOG).unwrap(), expected);
    }

    fn finish(mut self) {
        self.say("exit");
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                self.child.kill().unwrap();
                let status = self.child.wait().unwrap();
                assert!(
                    status.success(),
                    "probe exceeded ten-second teardown watchdog"
                );
                break status;
            }
            thread::park_timeout(Duration::from_millis(10));
        };
        assert!(status.success());
        self.stdout.take().unwrap().finish();
        self.stderr.take().unwrap().finish();
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(stdout) = self.stdout.take() {
            stdout.finish();
        }
        if let Some(stderr) = self.stderr.take() {
            stderr.finish();
        }
    }
}

#[test]
fn late_keyring_writes_keep_the_lock_for_both_timeout_causes_until_holder_exit() {
    for cause in ["command", "operation"] {
        let dir = tempfile::tempdir().unwrap();
        let mut child = Probe::spawn(dir.path(), cause);
        child.marker("timeout-old-record");
        let name = ServerName::parse("demo").unwrap();
        assert_eq!(
            lock::server_lock(dir.path(), &name, Duration::ZERO, None)
                .unwrap_err()
                .kind(),
            ErrorKind::CredentialLockTimeout
        );
        child.say("release");
        child.marker("completed-new-record");
        assert_eq!(
            lock::server_lock(dir.path(), &name, Duration::ZERO, None)
                .unwrap_err()
                .kind(),
            ErrorKind::CredentialLockTimeout
        );
        child.finish();
        lock::server_lock(dir.path(), &name, Duration::ZERO, None).unwrap();
    }
}
