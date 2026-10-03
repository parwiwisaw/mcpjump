//! Parses arguments, builds the command context, dispatches, and turns the
//! result into output and an exit code.

use std::ffi::OsString;
use std::io::{self, Write};

use clap::{Parser, ValueEnum};

use crate::cli::Cli;
use crate::commands::{self, Console, Context, Reply};
use crate::config::io::{ConfigFile, config_dir};
use crate::config::model::OutputFormat;
use crate::error::{Error, ErrorKind};
use crate::mcp::connector::SessionConnector;
use crate::output;
use crate::store::select::StoreOpener;
use crate::sys::Platform;
use crate::sys::browser::BrowserOpener;
use crate::sys::clock::Clock;
use crate::sys::env::Env;
use crate::sys::terminal::Terminal;

/// Exit code for success.
const EXIT_OK: u8 = 0;
/// Exit code for a tool that reported `isError: true`.
const EXIT_TOOL_ERROR: u8 = 1;
/// Exit code for a usage error reported by clap.
const EXIT_USAGE: u8 = 2;

/// The real system services, built in `main.rs` and fakes in tests.
#[derive(Debug)]
pub struct Deps<'a> {
    /// Environment variables.
    pub env: &'a dyn Env,
    /// Opens MCP sessions.
    pub connector: &'a dyn SessionConnector,
    /// Reads params from stdin.
    pub terminal: &'a dyn Terminal,
    /// Opens the credential stores.
    pub stores: &'a dyn StoreOpener,
    /// The wall clock, for token expiry.
    pub clock: &'a dyn Clock,
    /// Opens the authorization URL in a browser.
    pub browser: &'a dyn BrowserOpener,
}

/// Runs the CLI and returns the exit code.
///
/// `out` receives results only; `err` receives diagnostics.
pub fn run<I, T>(args: I, deps: &Deps<'_>, out: &mut dyn Write, err: &mut dyn Write) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    match Cli::try_parse_from(&args) {
        Ok(cli) => execute(cli, deps, out, err),
        Err(parse_error) => render_parse_error(&parse_error, &args, deps, out, err),
    }
}

fn execute(cli: Cli, deps: &Deps<'_>, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let context = match open_context(deps) {
        Ok(context) => context,
        Err(error) => return fail(&error, cli.output.unwrap_or_default(), err),
    };
    let format = cli.output.unwrap_or(context.config.settings.output);
    let ran = commands::run(cli.command, &context, deps, &mut Console::new(err, format));
    match ran {
        Ok(reply) => emit(&reply, format, out, err),
        Err(error) => fail(&error, format, err),
    }
}

fn open_context(deps: &Deps<'_>) -> Result<Context, Error> {
    let file = ConfigFile::new(config_dir(deps.env, Platform::CURRENT)?);
    let config = file.load()?;
    Ok(Context { file, config })
}

/// Writes the warnings to stderr and the result to stdout. A tool that
/// reported an error exits 1 once its result is written.
fn emit(reply: &Reply, format: OutputFormat, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    for warning in &reply.warnings {
        report(err, &output::render_warning(warning, format));
    }
    match write_or_fail(out, err, &output::render(&reply.value, format), format) {
        EXIT_OK if reply.tool_error => EXIT_TOOL_ERROR,
        code => code,
    }
}

/// Reports an error on stderr and returns its exit code.
fn fail(error: &Error, format: OutputFormat, err: &mut dyn Write) -> u8 {
    report(err, &output::render_error(error, format));
    error.kind().exit_code()
}

/// Writes clap's help or version to stdout, and a usage error to stderr in
/// the requested format. Help shown because arguments are missing stays text.
fn render_parse_error(
    parse_error: &clap::Error,
    args: &[OsString],
    deps: &Deps<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let text = parse_error.render().to_string();
    if !parse_error.use_stderr() {
        return write_or_fail(out, err, &text, OutputFormat::Text);
    }
    let is_help =
        parse_error.kind() == clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand;
    if is_help || parse_failure_format(args, deps) == OutputFormat::Text {
        report(err, &text);
        return EXIT_USAGE;
    }
    let first_line = text.lines().next().unwrap_or_default();
    let message = first_line.strip_prefix("error: ").unwrap_or(first_line);
    fail(
        &Error::new(ErrorKind::Usage, message),
        OutputFormat::Json,
        err,
    )
}

/// The output format for an error found while parsing: the last valid
/// `-o`/`--output` before `--`, else the config setting, else the default.
fn parse_failure_format(args: &[OsString], deps: &Deps<'_>) -> OutputFormat {
    requested_format(args).unwrap_or_else(|| {
        open_context(deps).map_or_else(
            |_| OutputFormat::default(),
            |context| context.config.settings.output,
        )
    })
}

fn requested_format(args: &[OsString]) -> Option<OutputFormat> {
    let mut format = None;
    let mut args = args.iter().skip(1).map(|arg| arg.to_str());
    while let Some(arg) = args.next() {
        let value = match arg {
            Some("--") => break,
            Some("-o" | "--output") => args.next().flatten(),
            Some(arg) => arg
                .strip_prefix("--output=")
                .or_else(|| arg.strip_prefix("-o")),
            None => None,
        };
        format = value
            .and_then(|value| OutputFormat::from_str(value, false).ok())
            .or(format);
    }
    format
}

/// Writes `text` to `out`; if that fails, reports `output_io`. A reader
/// that stopped early (`| head`) closed the pipe on purpose, so that ends
/// quietly.
fn write_or_fail(out: &mut dyn Write, err: &mut dyn Write, text: &str, format: OutputFormat) -> u8 {
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => EXIT_OK,
        Err(write_error) if write_error.kind() == io::ErrorKind::BrokenPipe => EXIT_OK,
        Err(write_error) => {
            let error = Error::new(
                ErrorKind::OutputIo,
                format!("cannot write output: {write_error}"),
            );
            fail(&error, format, err)
        }
    }
}

/// Writes a diagnostic. If stderr itself is unwritable there is nowhere left
/// to report to, so the failure is dropped and the exit code carries it.
fn report(err: &mut dyn Write, text: &str) {
    let _unreportable = err.write_all(text.as_bytes()).and_then(|()| err.flush());
}
