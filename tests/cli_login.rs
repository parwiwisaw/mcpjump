//! `login`, `tools` and `logout` through the built binary, its real HTTP
//! client and loopback callback, against the fixture authorization server.
//! Test code may unwrap: a panic is a test failure with its location.
#![allow(clippy::unwrap_used)]

#[allow(dead_code)]
#[path = "integration/support/oauth_server.rs"]
mod oauth_server;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use assert_cmd::Command as AssertCommand;
use serde_json::Value;
use tempfile::TempDir;

use crate::oauth_server::{OAuthServer, Script};

fn home(server: &OAuthServer) -> TempDir {
    let home = tempfile::tempdir().unwrap();
    let config = format!(
        "[settings]\ncredential_store = \"file\"\n\n[servers.demo]\nurl = \"{}\"\n",
        server.mcp_url()
    );
    std::fs::write(home.path().join("config.toml"), config).unwrap();
    home
}

/// Follows `url` and its redirects, as a browser would.
fn open(url: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let page = runtime.block_on(reqwest::get(url)).unwrap();
    assert!(page.status().is_success(), "{}", page.status());
}

fn mcpjump(home: &TempDir, args: &[&str]) -> std::process::Output {
    AssertCommand::new(env!("CARGO_BIN_EXE_mcpjump"))
        .env("MCPJUMP_HOME", home.path())
        .args(args)
        .output()
        .unwrap()
}

/// Logs in to `demo` with `--no-browser`, following the printed URL.
fn login(home: &TempDir) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mcpjump"))
        .env("MCPJUMP_HOME", home.path())
        .args(["login", "demo", "--no-browser"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    let notice: Value = serde_json::from_str(&line).unwrap();
    open(notice["authorize"]["url"].as_str().unwrap());
    child.wait_with_output().unwrap()
}

#[test]
fn a_login_through_the_loopback_callback_is_used_and_logged_out() {
    let server = OAuthServer::start(Script::default());
    let home = home(&server);
    let output = login(&home);
    assert_eq!(output.status.code(), Some(0));
    let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reply["logged_in"], true);
    assert_eq!(reply["backend"], "file (unencrypted)");
    let tokens = home.path().join("credentials/demo.tokens.json");
    assert!(tokens.exists());

    let listed = mcpjump(&home, &["tools", "demo"]);
    assert_eq!(listed.status.code(), Some(3));
    let stderr = String::from_utf8(listed.stderr).unwrap();
    assert!(stderr.contains("run `mcpjump login demo`"), "{stderr}");
    let bearers: Vec<_> = server
        .to("/mcp")
        .into_iter()
        .filter_map(|request| request.authorization)
        .collect();
    assert_eq!(bearers, ["Bearer at-1", "Bearer at-2"]);

    let logged_out = mcpjump(&home, &["logout", "demo"]);
    assert_eq!(logged_out.status.code(), Some(0));
    assert!(!tokens.exists());
}

#[test]
fn two_runs_racing_a_rotating_server_both_succeed() {
    let server = OAuthServer::start(Script {
        serve_mcp: true,
        expires_in: Some(60),
        ..Script::default()
    });
    let home = home(&server);
    assert_eq!(login(&home).status.code(), Some(0));
    let runs: Vec<_> = (0..2)
        .map(|_| {
            Command::new(env!("CARGO_BIN_EXE_mcpjump"))
                .env("MCPJUMP_HOME", home.path())
                .args(["tools", "demo"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for run in runs {
        let output = run.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{stderr}");
        assert_eq!(output.stdout, b"[]\n");
    }
    let refreshes: Vec<_> = server
        .to("/token")
        .into_iter()
        .filter_map(|request| request.params.get("refresh_token").cloned())
        .collect();
    // The second run waits for the lock, then uses the first run's new
    // token: refresh token rt-1 is spent once.
    assert_eq!(refreshes, ["rt-1"]);
    assert_eq!(mcpjump(&home, &["tools", "demo"]).status.code(), Some(0));
}
