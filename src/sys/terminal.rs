//! The terminal: standard input for `run <server> <tool> -`, and for a
//! redirect URL pasted during `login`.

use std::fmt::Debug;
use std::io::{self, BufRead, BufReader, IsTerminal, Read};
use std::thread;
use std::time::Duration;

use tokio::sync::mpsc::{Receiver, Sender, channel};

use crate::error::{Error, ErrorKind};
use crate::sys::worker::run_within;

/// Reads from the user's terminal.
pub trait Terminal: Debug + Sync {
    /// Reads all of standard input as UTF-8, at most `limit` bytes, within
    /// `timeout`.
    ///
    /// # Errors
    /// `invalid_params` if the input is too large, not UTF-8, unreadable, or
    /// does not end in time.
    fn read_stdin(&self, limit: u64, timeout: Duration) -> Result<String, Error>;

    /// Lines the user pastes, each at most [`MAX_PASTE_BYTES`] plus one,
    /// trimmed, blank lines skipped. `None` when stdin is not a terminal.
    fn paste(&self) -> Option<Receiver<String>>;
}

/// Longest pasted line accepted; a longer one arrives cut, and is rejected.
pub const MAX_PASTE_BYTES: u64 = 8 * 1024;

/// The process's standard streams. Constructed only in `main.rs`.
#[derive(Debug)]
pub struct StdTerminal;

impl Terminal for StdTerminal {
    fn read_stdin(&self, limit: u64, timeout: Duration) -> Result<String, Error> {
        let read = Box::new(move || read_bounded(&mut io::stdin().lock(), limit));
        run_within(read, timeout).unwrap_or_else(|| Err(stdin_timeout(timeout)))
    }

    fn paste(&self) -> Option<Receiver<String>> {
        paste_lines(io::stdin().is_terminal(), Box::new(io::stdin()))
    }
}

/// Reads pasted lines from `reader` on a thread of its own, when `is_tty`.
/// The thread ends at end of input or once the receiver is dropped; a
/// thread still blocked on the terminal is abandoned when the process exits.
#[must_use]
pub fn paste_lines(is_tty: bool, reader: Box<dyn Read + Send>) -> Option<Receiver<String>> {
    is_tty.then(|| {
        let (sender, receiver) = channel(1);
        thread::spawn(move || pump(&mut BufReader::new(reader), &sender));
        receiver
    })
}

/// Sends each non-blank line until end of input, a read error, or a closed
/// channel. One line in flight at a time bounds the memory used.
pub fn pump(reader: &mut dyn BufRead, sender: &Sender<String>) {
    loop {
        let mut line = Vec::new();
        match reader
            .take(MAX_PASTE_BYTES + 1)
            .read_until(b'\n', &mut line)
        {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let text = String::from_utf8_lossy(&line).trim().to_owned();
        if !text.is_empty() && sender.blocking_send(text).is_err() {
            return;
        }
    }
}

/// Reads `reader` to the end, keeping at most `limit` bytes plus one to
/// detect an oversized input.
///
/// # Errors
/// `invalid_params` if the input is larger than `limit`, not UTF-8, or the
/// read fails.
pub fn read_bounded(reader: &mut dyn Read, limit: u64) -> Result<String, Error> {
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| stdin_error(&format!("cannot be read: {error}")))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(params_too_large(limit));
    }
    String::from_utf8(bytes).map_err(|_| stdin_error("is not UTF-8"))
}

/// The error for params larger than `max_params_bytes`.
#[must_use]
pub fn params_too_large(limit: u64) -> Error {
    Error::new(
        ErrorKind::InvalidParams,
        format!("params are larger than max_params_bytes ({limit})"),
    )
}

/// The error for stdin that stays open past `stdin_timeout_secs`.
#[must_use]
pub fn stdin_timeout(timeout: Duration) -> Error {
    stdin_error(&format!(
        "did not end within stdin_timeout_secs ({})",
        timeout.as_secs()
    ))
}

fn stdin_error(what: &str) -> Error {
    Error::new(ErrorKind::InvalidParams, format!("params on stdin {what}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Broken;

    impl Read for Broken {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("gone"))
        }
    }

    #[test]
    fn input_up_to_the_limit_is_read() {
        assert_eq!(read_bounded(&mut &b"{}"[..], 2), Ok("{}".to_owned()));
    }

    #[test]
    fn oversized_broken_and_binary_input_is_invalid_params() {
        let cases: [(&mut dyn Read, &str); 3] = [
            (&mut &b"{} "[..], "max_params_bytes"),
            (&mut Broken, "cannot be read: gone"),
            (&mut &[0xff_u8][..], "not UTF-8"),
        ];
        for (reader, text) in cases {
            let error = read_bounded(reader, 2).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidParams);
            assert!(error.message().contains(text));
        }
    }

    #[test]
    fn pasted_lines_arrive_trimmed_without_blanks() {
        assert!(paste_lines(false, Box::new(io::empty())).is_none());
        let mut receiver = paste_lines(true, Box::new(&b" a \n\n\nb"[..])).unwrap();
        assert_eq!(receiver.blocking_recv().as_deref(), Some("a"));
        assert_eq!(receiver.blocking_recv().as_deref(), Some("b"));
        assert_eq!(receiver.blocking_recv(), None);
    }

    #[test]
    fn a_long_line_arrives_cut_and_the_pump_stops_on_errors() {
        let long = vec![b'x'; 9000];
        let (sender, mut receiver) = channel(4);
        pump(&mut &long[..], &sender);
        assert_eq!(receiver.blocking_recv().map(|line| line.len()), Some(8193));
        pump(&mut BufReader::new(Broken), &sender);
        drop(receiver);
        pump(&mut &b"line\nmore\n"[..], &sender);
    }

    #[test]
    fn the_timeout_names_the_limit() {
        let error = stdin_timeout(Duration::from_secs(7));
        assert!(error.message().contains("stdin_timeout_secs (7)"));
    }
}
