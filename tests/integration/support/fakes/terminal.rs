//! A `Terminal` that answers with scripted text.

use std::sync::Mutex;
use std::time::Duration;

use mcpjump::error::Error;
use mcpjump::sys::terminal::Terminal;
use tokio::sync::mpsc::{Receiver, Sender, channel};

/// Answers every read with `answer` and records the bounds it was given.
/// Pasted lines are scripted too; without them stdin is not a terminal.
#[derive(Debug)]
pub(crate) struct ScriptedTerminal {
    answer: Result<String, Error>,
    pub(crate) reads: Mutex<Vec<(u64, Duration)>>,
    pastes: Mutex<Option<Receiver<String>>>,
}

impl ScriptedTerminal {
    /// A terminal whose stdin holds `answer`, or fails with it.
    pub(crate) fn new(answer: Result<String, Error>) -> Self {
        Self {
            answer,
            reads: Mutex::default(),
            pastes: Mutex::default(),
        }
    }

    /// A terminal where the user pastes `lines`, then stops typing.
    pub(crate) fn pasting(lines: &[&str]) -> Self {
        let (terminal, sender) = Self::piped(lines.len().max(1));
        for line in lines {
            sender.try_send((*line).to_owned()).unwrap();
        }
        terminal
    }

    /// A terminal where the user pastes whatever is sent on the returned
    /// channel, which holds up to `capacity` lines.
    pub(crate) fn piped(capacity: usize) -> (Self, Sender<String>) {
        let (sender, receiver) = channel(capacity);
        let terminal = Self::default();
        *terminal.pastes.lock().unwrap() = Some(receiver);
        (terminal, sender)
    }
}

impl Default for ScriptedTerminal {
    fn default() -> Self {
        Self::new(Ok("{}".to_owned()))
    }
}

impl Terminal for ScriptedTerminal {
    fn read_stdin(&self, limit: u64, timeout: Duration) -> Result<String, Error> {
        self.reads.lock().unwrap().push((limit, timeout));
        self.answer.clone()
    }

    fn paste(&self) -> Option<Receiver<String>> {
        self.pastes.lock().unwrap().take()
    }
}
