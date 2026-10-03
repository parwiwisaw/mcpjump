//! Shared test helpers: fakes for the system seams and a harness that runs
//! the CLI in-process against a temporary config directory.

pub(crate) mod auth;
pub(crate) mod fakes;
pub(crate) mod http;
pub(crate) mod mcp_client;
pub(crate) mod mcp_server;
pub(crate) mod oauth_server;
pub(crate) mod raw_mcp_server;

use std::io::{self, Write};
use std::path::PathBuf;

use serde_json::Value;
use tempfile::TempDir;

use fakes::browser::RecordingBrowser;
use fakes::clock::FixedClock;
use fakes::connector::FakeConnector;
use fakes::env::MapEnv;
use fakes::store::FakeOpener;
use fakes::terminal::ScriptedTerminal;

/// A config directory, environment, connector and terminal for in-process
/// CLI runs.
pub(crate) struct Harness {
    pub(crate) home: TempDir,
    pub(crate) env: MapEnv,
    pub(crate) connector: FakeConnector,
    pub(crate) terminal: ScriptedTerminal,
    pub(crate) stores: FakeOpener,
    pub(crate) clock: FixedClock,
    pub(crate) browser: RecordingBrowser,
}

impl Harness {
    /// A harness whose `MCPJUMP_HOME` is a fresh temporary directory.
    pub(crate) fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let env = MapEnv::default().with("MCPJUMP_HOME", home.path().to_str().unwrap());
        Self {
            home,
            env,
            connector: FakeConnector::default(),
            terminal: ScriptedTerminal::default(),
            stores: FakeOpener::default(),
            clock: FixedClock::default(),
            browser: RecordingBrowser::default(),
        }
    }

    /// The config file path.
    pub(crate) fn config_path(&self) -> PathBuf {
        self.home.path().join("config.toml")
    }

    /// The config file's text.
    pub(crate) fn config_text(&self) -> String {
        std::fs::read_to_string(self.config_path()).unwrap()
    }

    /// Writes the config file.
    pub(crate) fn write_config(&self, text: &str) {
        std::fs::write(self.config_path(), text).unwrap();
    }

    /// Runs `mcpjump <args>` with in-memory stdout and stderr.
    pub(crate) fn run(&self, args: &[&str]) -> Outcome {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = self.run_with(args, &mut out, &mut err);
        Outcome {
            code,
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
        }
    }

    /// Runs `mcpjump <args>` with the given writers.
    pub(crate) fn run_with(&self, args: &[&str], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
        let deps = self.deps();
        let command_line = std::iter::once("mcpjump").chain(args.iter().copied());
        mcpjump::run(command_line, &deps, out, err)
    }
}

impl Harness {
    /// The seams, all fakes.
    pub(crate) fn deps(&self) -> mcpjump::Deps<'_> {
        mcpjump::Deps {
            env: &self.env,
            connector: &self.connector,
            terminal: &self.terminal,
            stores: &self.stores,
            clock: &self.clock,
            browser: &self.browser,
        }
    }
}

/// The result of one CLI run.
#[derive(Debug)]
pub(crate) struct Outcome {
    pub(crate) code: u8,
    pub(crate) out: String,
    pub(crate) err: String,
}

impl Outcome {
    /// Stdout parsed as JSON, after checking the run succeeded quietly.
    pub(crate) fn json(&self) -> Value {
        assert_eq!(
            (self.code, self.err.as_str()),
            (0, ""),
            "stdout: {}",
            self.out
        );
        serde_json::from_str(&self.out).unwrap()
    }

    /// The error kind from stderr JSON, after checking stdout is empty.
    pub(crate) fn error_kind(&self) -> String {
        assert_eq!(self.out, "");
        let error: Value = serde_json::from_str(&self.err).unwrap();
        error["error"]["kind"].as_str().unwrap().to_owned()
    }
}

/// A writer that always fails.
pub(crate) struct BrokenWriter;

impl Write for BrokenWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("closed"))
    }
}

/// A pipe whose reader has gone, as after `| head`.
pub(crate) struct ClosedPipe;

impl Write for ClosedPipe {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
