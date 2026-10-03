//! One module per subcommand. A command validates its arguments, does its
//! work through the context and the injected seams, and returns its reply.

mod add;
mod add_json;
pub(crate) mod connect;
mod get;
mod list;
mod login;
mod logout;
mod remove;
mod run;
mod tools;

use std::io::{self, Write};

use futures::future::LocalBoxFuture;
use serde_json::Value;

use crate::app::Deps;
use crate::cli::Command;
use crate::config::io::ConfigFile;
use crate::config::model::{Config, OutputFormat};
use crate::error::{Error, ErrorKind};
use crate::output;

/// What every command may use. Built once per process by `app`.
#[derive(Debug)]
pub(crate) struct Context {
    /// The config file, for updates.
    pub(crate) file: ConfigFile,
    /// The config as loaded at start.
    pub(crate) config: Config,
}

/// A command's result, and what goes to stderr beside it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Reply {
    /// The result for stdout.
    pub(crate) value: Value,
    /// Whether the tool reported `isError: true`: exit 1, result still printed.
    pub(crate) tool_error: bool,
    /// Warnings for stderr. Never server-supplied text.
    pub(crate) warnings: Vec<String>,
}

impl From<Value> for Reply {
    fn from(value: Value) -> Self {
        Self {
            value,
            tool_error: false,
            warnings: Vec::new(),
        }
    }
}

/// Diagnostics a command writes to stderr while it runs, such as the
/// authorization URL a login waits on.
pub(crate) struct Console<'a> {
    err: &'a mut dyn Write,
    format: OutputFormat,
}

impl<'a> Console<'a> {
    pub(crate) fn new(err: &'a mut dyn Write, format: OutputFormat) -> Self {
        Self { err, format }
    }

    /// Writes a warning now.
    pub(crate) fn warn(&mut self, message: &str) {
        self.write(&output::render_warning(message, self.format));
    }

    /// Writes `text`, or `value` as JSON, now.
    pub(crate) fn notice(&mut self, text: &str, value: &Value) {
        self.write(&output::render_notice(text, value, self.format));
    }

    /// A stderr that cannot be written has nowhere to report to; the
    /// command's own result still decides the exit code.
    fn write(&mut self, text: &str) {
        let _unreportable = self
            .err
            .write_all(text.as_bytes())
            .and_then(|()| self.err.flush());
    }
}

/// Runs one subcommand.
pub(crate) fn run(
    command: Command,
    context: &Context,
    deps: &Deps<'_>,
    console: &mut Console<'_>,
) -> Result<Reply, Error> {
    match command {
        Command::Add(args) => add::run(args, context).map(Reply::from),
        Command::AddJson(args) => add_json::run(&args, context).map(Reply::from),
        Command::List => Ok(Reply::from(list::run(context))),
        Command::Get(args) => get::run(&args.name, context).map(Reply::from),
        Command::Remove(args) => remove::run(&args.name, context, deps).map(Reply::from),
        Command::Tools(args) => block_on(Box::pin(tools::run(args, context, deps))),
        Command::Run(args) => block_on(Box::pin(run::run(args, context, deps))),
        Command::Login(args) => block_on(Box::pin(login::run(args, context, deps, console))),
        Command::Logout(args) => logout::run(&args.name, context, deps).map(Reply::from),
    }
}

/// Runs a network command on a single-threaded runtime: mcpjump sends one
/// request at a time.
fn block_on(work: LocalBoxFuture<'_, Result<Reply, Error>>) -> Result<Reply, Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(runtime_error)
        .and_then(|runtime| runtime.block_on(work))
}

/// The OS refused the timer or I/O driver, e.g. out of file descriptors.
fn runtime_error(_cause: io::Error) -> Error {
    Error::new(ErrorKind::Network, "cannot start the network runtime")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_runtime_failure_is_a_network_error() {
        let error = runtime_error(io::Error::other("no fds"));
        assert_eq!(error.kind(), ErrorKind::Network);
    }
}
