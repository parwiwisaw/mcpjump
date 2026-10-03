//! `run <server> <tool> -` through the built binary's real stdin. Test code
//! may unwrap: a panic is a test failure with its location.
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command as AssertCommand;
use tempfile::TempDir;

const CONFIG: &str = "[limits]\nstdin_timeout_secs = 1\n\n\
    [servers.demo]\nurl = \"https://a.example/mcp\"\n";

fn home() -> TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), CONFIG).unwrap();
    home
}

#[test]
fn params_are_read_from_stdin() {
    let home = home();
    let assert = AssertCommand::new(env!("CARGO_BIN_EXE_mcpjump"))
        .env("MCPJUMP_HOME", home.path())
        .args(["run", "demo", "t", "-"])
        .write_stdin("[1]")
        .assert()
        .code(2)
        .stdout("");
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("params must be a JSON object"), "{stderr}");
}

#[test]
fn stdin_left_open_times_out() {
    let home = home();
    let mut child = Command::new(env!("CARGO_BIN_EXE_mcpjump"))
        .env("MCPJUMP_HOME", home.path())
        .args(["run", "demo", "t", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut held_open = child.stdin.take().unwrap();
    held_open.write_all(b"{").unwrap();
    let started = Instant::now();
    let output = child.wait_with_output().unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("did not end within stdin_timeout_secs (1)"),
        "{stderr}"
    );
    drop(held_open);
}
