//! Locating, loading and updating the config file.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::time::Instant;
use toml_edit::DocumentMut;

use crate::config::document;
use crate::config::model::{Config, RawConfig};
use crate::error::{Error, ErrorKind};
use crate::files;
use crate::sys::Platform;
use crate::sys::deadline::{self, Limit, clipped_wait};
use crate::sys::env::Env;

/// Largest config file accepted.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// The file written on first update: every setting with its default, commented.
pub const TEMPLATE: &str = include_str!("default.toml");

/// Finds the config directory: `MCPJUMP_HOME`, else `XDG_CONFIG_HOME/mcpjump`
/// or `~/.config/mcpjump` on Unix, else `%APPDATA%\mcpjump` on Windows. A
/// relative base is ignored, since it would change with the working directory.
///
/// # Errors
/// `config_io` if `MCPJUMP_HOME` is relative or no absolute base is set.
pub fn config_dir(env: &dyn Env, platform: Platform) -> Result<PathBuf, Error> {
    if let Some(home) = non_empty(env, "MCPJUMP_HOME") {
        let home = PathBuf::from(home);
        if home.is_absolute() {
            return Ok(home);
        }
        return Err(Error::new(
            ErrorKind::ConfigIo,
            "MCPJUMP_HOME must be an absolute path",
        ));
    }
    let base = match platform {
        Platform::Unix => absolute(env, "XDG_CONFIG_HOME")
            .or_else(|| absolute(env, "HOME").map(|home| home.join(".config"))),
        Platform::Windows => absolute(env, "APPDATA"),
    };
    base.map(|base| base.join("mcpjump")).ok_or_else(|| {
        Error::new(
            ErrorKind::ConfigIo,
            "cannot find a config directory; set MCPJUMP_HOME",
        )
    })
}

fn non_empty(env: &dyn Env, name: &str) -> Option<String> {
    env.var(name).filter(|value| !value.is_empty())
}

fn absolute(env: &dyn Env, name: &str) -> Option<PathBuf> {
    non_empty(env, name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// The config file in one directory.
#[derive(Debug, Clone)]
pub struct ConfigFile {
    dir: PathBuf,
}

impl ConfigFile {
    /// The config file inside `dir`. Nothing is read or created yet.
    #[must_use]
    pub const fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// The config directory, which also holds credentials and locks.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The path of `config.toml`.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.dir.join("config.toml")
    }

    /// Loads and validates the config. A missing file yields the defaults.
    ///
    /// # Errors
    /// `config_io`, `config_too_large` or `config_invalid`.
    pub fn load(&self) -> Result<Config, Error> {
        parse(&self.read()?)
    }

    /// Applies `edit` under the config lock: re-reads the file (or the
    /// template), edits it, checks the result's size and validity, and
    /// replaces the file atomically. Nothing is written if any step fails, so
    /// an update never leaves a file the next load would reject.
    ///
    /// # Errors
    /// `config_lock_timeout`, the edit's error, `config_too_large`, or a load
    /// or write error.
    pub fn update(
        &self,
        wait: Duration,
        edit: &dyn Fn(&mut DocumentMut) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.update_with_deadline(wait, None, edit)
    }

    /// Applies an update without waiting past an optional command deadline.
    ///
    /// # Errors
    /// Those of [`Self::update`]; `request_timeout` when the command expires.
    pub fn update_with_deadline(
        &self,
        wait: Duration,
        command_deadline: Option<Instant>,
        edit: &dyn Fn(&mut DocumentMut) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let lock_path = self.dir.join("locks").join("config.lock");
        let _lock = deadline::operation(command_deadline, || {
            let budget = clipped_wait(wait, command_deadline, Instant::now());
            files::lock(&lock_path, budget.duration).map_err(|error| {
                if error.kind() == io::ErrorKind::TimedOut && budget.limit == Limit::Command {
                    deadline::timeout()
                } else {
                    io_error(&lock_path, &error)
                }
            })
        })?;
        let mut doc = deadline::operation(command_deadline, || {
            let text = self.read()?;
            let doc = text
                .parse::<DocumentMut>()
                .map_err(|error| syntax_error(&text, error.message(), error.span()))?;
            document::check_server_names(&doc)?;
            Ok(doc)
        })?;
        edit(&mut doc)?;
        let text = doc.to_string();
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(Error::new(
                ErrorKind::ConfigTooLarge,
                format!("config.toml would exceed {MAX_CONFIG_BYTES} bytes; nothing was written"),
            ));
        }
        parse(&text)?;
        deadline::check(command_deadline)?;
        let path = self.path();
        files::write_atomic(&path, text.as_bytes()).map_err(|error| io_error(&path, &error))
    }

    fn read(&self) -> Result<String, Error> {
        let path = self.path();
        files::read_bounded(&path, MAX_CONFIG_BYTES)
            .map(|text| text.unwrap_or_else(|| TEMPLATE.to_owned()))
            .map_err(|error| io_error(&path, &error))
    }
}

/// Parses and validates config text.
fn parse(text: &str) -> Result<Config, Error> {
    toml_edit::de::from_str::<RawConfig>(text)
        .map_err(|error| syntax_error(text, error.message(), error.span()))?
        .validate()
}

/// A parse error naming the line but never quoting it, since the line may
/// hold a header secret. Quoted values in the parser's message are redacted
/// for the same reason.
fn syntax_error(text: &str, message: &str, span: Option<std::ops::Range<usize>>) -> Error {
    let line = span.map_or(String::new(), |span| {
        let line = text.get(..span.start).unwrap_or(text).matches('\n').count() + 1;
        format!(" (line {line})")
    });
    Error::new(
        ErrorKind::ConfigInvalid,
        format!("config.toml{line}: {}", redact_quoted(message)),
    )
}

/// Replaces every double-quoted string, such as serde's `string "value"`,
/// with `"[redacted]"`. Backslash escapes inside the quotes are skipped; an
/// unterminated quote redacts the rest of the message.
fn redact_quoted(message: &str) -> String {
    let mut redacted = String::with_capacity(message.len());
    let mut chars = message.chars();
    while let Some(c) = chars.next() {
        if c != '"' {
            redacted.push(c);
            continue;
        }
        redacted.push_str("\"[redacted]\"");
        while let Some(quoted) = chars.next() {
            match quoted {
                '\\' => {
                    chars.next();
                }
                '"' => break,
                _ => {}
            }
        }
    }
    redacted
}

fn io_error(path: &Path, error: &io::Error) -> Error {
    let kind = match error.kind() {
        io::ErrorKind::FileTooLarge => ErrorKind::ConfigTooLarge,
        io::ErrorKind::TimedOut => ErrorKind::ConfigLockTimeout,
        _ => ErrorKind::ConfigIo,
    };
    Error::new(kind, format!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::redact_quoted;

    #[test]
    fn quoted_text_is_redacted_to_the_end_when_unterminated() {
        assert_eq!(
            redact_quoted(r#"a "x\"y" b "open"#),
            r#"a "[redacted]" b "[redacted]""#
        );
    }
}
