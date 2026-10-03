//! Size- and time-bounded server-sent events: a byte guard in front of
//! `sse-stream`, which bounds neither lines nor events itself.
//!
//! A JSON-RPC message arrives as one `data:` line, so a line may be as large as
//! an event, and one counter bounds both.

use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;
use futures::stream::{self, BoxStream, StreamExt};
use reqwest::Response;
use sse_stream::{Error as SseError, Sse, SseStream};
use tokio::time::{Instant, timeout_at};

use crate::error::{Error, ErrorKind};
use crate::http::client::network_error;

/// The most events the parser may hold from one chunk. The guard cuts every
/// chunk after this many events, so a chunk of tiny events can't make the
/// parser buffer an unbounded queue.
pub const MAX_BUFFERED_EVENTS: usize = 64;

/// Limits for one SSE stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SseLimits {
    /// Largest event, counted in bytes of field content: `max_response_bytes`.
    pub max_event_bytes: usize,
    /// Longest wait for the next complete line, comments included:
    /// `stream_idle_secs`.
    pub idle: Duration,
    /// When the whole stream must end: the command's deadline.
    pub deadline: Instant,
}

/// Parses `response` as SSE. The stream ends with an error when an event
/// exceeds its size, no complete line arrives within `idle`, the deadline
/// passes, or the transfer breaks. Those errors are
/// [`SseError::Body`] holding an [`Error`] with the matching kind. An error
/// ends the stream at once: events still queued from the chunk that caused
/// it are discarded.
pub fn events(response: Response, limits: SseLimits) -> BoxStream<'static, Result<Sse, SseError>> {
    let reader = Reader {
        origin: response.url().origin().ascii_serialization(),
        body: response.bytes_stream().boxed(),
        guard: SseGuard::new(limits.max_event_bytes),
        pending: VecDeque::new(),
        idle: limits.idle,
        deadline: limits.deadline,
        last_line: Instant::now(),
        failed: false,
    };
    SseStream::from_bytes_stream(stream::unfold(reader, Reader::next)).boxed()
}

/// The mcpjump error behind a failed stream item: the bounded reader's own
/// error, or `protocol_error` when the server sent malformed SSE.
#[must_use]
pub fn stream_error(error: &SseError, origin: &str) -> Error {
    let own = match error {
        SseError::Body(inner) => inner.downcast_ref::<Error>(),
        _ => None,
    };
    own.cloned().unwrap_or_else(|| {
        Error::new(
            ErrorKind::ProtocolError,
            format!("{origin} sent a malformed SSE stream"),
        )
    })
}

/// Feeds the parser one guarded chunk at a time, under the idle and deadline
/// timers.
struct Reader {
    origin: String,
    body: BoxStream<'static, reqwest::Result<Bytes>>,
    guard: SseGuard,
    pending: VecDeque<Bytes>,
    idle: Duration,
    deadline: Instant,
    last_line: Instant,
    failed: bool,
}

impl Reader {
    async fn next(mut self) -> Option<(Result<Bytes, Error>, Self)> {
        if self.failed {
            return None;
        }
        if let Some(part) = self.pending.pop_front() {
            return Some((Ok(part), self));
        }
        let idle_deadline = self.last_line + self.idle;
        let item = match timeout_at(idle_deadline.min(self.deadline), self.body.next()).await {
            Ok(None) => return None,
            Ok(Some(Ok(chunk))) => self.accept(chunk),
            Ok(Some(Err(error))) => Err(network_error(&error, &self.origin)),
            Err(_) => Err(self.timed_out(idle_deadline)),
        };
        self.failed = item.is_err();
        Some((item, self))
    }

    fn accept(&mut self, chunk: Bytes) -> Result<Bytes, Error> {
        if self.guard.feed(chunk, &mut self.pending)? {
            self.last_line = Instant::now();
        }
        Ok(self.pending.pop_front().unwrap_or_default())
    }

    fn timed_out(&self, idle_deadline: Instant) -> Error {
        let message = if idle_deadline < self.deadline {
            format!(
                "{} sent no complete SSE line for {:?}",
                self.origin, self.idle
            )
        } else {
            format!(
                "the SSE stream from {} did not finish before the deadline",
                self.origin
            )
        };
        Error::new(ErrorKind::StreamTimeout, message)
    }
}

/// Counts the bytes of the event being received, across chunks, and cuts
/// chunks after every [`MAX_BUFFERED_EVENTS`] events. Pure: no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseGuard {
    max_event_bytes: usize,
    event_bytes: usize,
    line_empty: bool,
    after_cr: bool,
}

/// What one byte did to the stream.
enum Step {
    Other,
    LineEnd,
    EventEnd,
}

impl SseGuard {
    /// A guard for a new stream.
    #[must_use]
    pub const fn new(max_event_bytes: usize) -> Self {
        Self {
            max_event_bytes,
            event_bytes: 0,
            line_empty: true,
            after_cr: false,
        }
    }

    /// Checks `chunk` and appends it to `out`, cut into parts of at most
    /// [`MAX_BUFFERED_EVENTS`] events each. Always appends at least one part.
    /// Returns whether the chunk completed a line.
    ///
    /// # Errors
    /// `response_too_large` as soon as the current event passes the limit.
    pub fn feed(&mut self, mut chunk: Bytes, out: &mut VecDeque<Bytes>) -> Result<bool, Error> {
        let original = chunk.clone();
        let (mut line_ended, mut events, mut cut) = (false, 0, 0);
        for (index, byte) in original.iter().enumerate() {
            match self.step(*byte)? {
                Step::Other => {}
                Step::LineEnd => line_ended = true,
                Step::EventEnd => {
                    line_ended = true;
                    events += 1;
                    if events == MAX_BUFFERED_EVENTS {
                        out.push_back(chunk.split_to(index + 1 - cut));
                        (events, cut) = (0, index + 1);
                    }
                }
            }
        }
        out.push_back(chunk);
        Ok(line_ended)
    }

    fn step(&mut self, byte: u8) -> Result<Step, Error> {
        let after_cr = std::mem::replace(&mut self.after_cr, byte == b'\r');
        match byte {
            b'\n' if after_cr => Ok(Step::Other),
            b'\r' | b'\n' => Ok(self.end_line()),
            _ => {
                self.line_empty = false;
                self.event_bytes += 1;
                if self.event_bytes > self.max_event_bytes {
                    return Err(Error::new(
                        ErrorKind::ResponseTooLarge,
                        format!("an SSE event is larger than {} bytes", self.max_event_bytes),
                    ));
                }
                Ok(Step::Other)
            }
        }
    }

    /// A blank line ends the event, if it had content.
    fn end_line(&mut self) -> Step {
        let blank = std::mem::replace(&mut self.line_empty, true);
        if blank && self.event_bytes > 0 {
            self.event_bytes = 0;
            Step::EventEnd
        } else {
            Step::LineEnd
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stream_error_keeps_the_readers_own_error() {
        let own = Error::new(ErrorKind::StreamTimeout, "idle");
        let wrapped = SseError::Body(Box::new(own.clone()));
        assert_eq!(stream_error(&wrapped, "https://a.example"), own);
    }

    #[test]
    fn any_other_stream_error_is_malformed_sse() {
        let foreign = SseError::Body("boom".into());
        for error in [foreign, SseError::InvalidLine] {
            let named = stream_error(&error, "https://a.example");
            assert_eq!(named.kind(), ErrorKind::ProtocolError);
        }
    }
}
