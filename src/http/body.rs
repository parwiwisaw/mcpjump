//! Size-bounded response bodies, read under a deadline.

use bytes::Bytes;
use reqwest::Response;
use tokio::time::{Instant, timeout_at};

use crate::error::{Error, ErrorKind};
use crate::http::client::{network_error, request_timeout};

/// A byte limit and the error kind reported when a body exceeds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeLimit {
    bytes: u64,
    kind: ErrorKind,
}

impl SizeLimit {
    /// `max_response_bytes`, for MCP responses.
    #[must_use]
    pub const fn response(bytes: u64) -> Self {
        Self {
            bytes,
            kind: ErrorKind::ResponseTooLarge,
        }
    }

    /// `max_metadata_bytes`, for resource and authorization-server metadata.
    #[must_use]
    pub const fn metadata(bytes: u64) -> Self {
        Self {
            bytes,
            kind: ErrorKind::MetadataTooLarge,
        }
    }

    fn exceeded(self, origin: &str) -> Error {
        Error::new(
            self.kind,
            format!(
                "the response from {origin} is larger than {} bytes",
                self.bytes
            ),
        )
    }
}

/// Reads the whole body. Fails before reading when `Content-Length` is over
/// the limit, and otherwise as soon as the bytes received would pass it.
///
/// # Errors
/// The limit's kind when the body is too large, `request_timeout` after
/// `deadline`, and `network` when the transfer breaks.
pub async fn read_body(
    mut response: Response,
    limit: SizeLimit,
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    let origin = response.url().origin().ascii_serialization();
    if response
        .content_length()
        .is_some_and(|length| length > limit.bytes)
    {
        return Err(limit.exceeded(&origin));
    }
    let max = usize::try_from(limit.bytes).unwrap_or(usize::MAX);
    let mut body = Vec::new();
    while let Some(chunk) = next_chunk(&mut response, deadline, &origin).await? {
        if chunk.len() > max - body.len() {
            return Err(limit.exceeded(&origin));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn next_chunk(
    response: &mut Response,
    deadline: Instant,
    origin: &str,
) -> Result<Option<Bytes>, Error> {
    match timeout_at(deadline, response.chunk()).await {
        Ok(chunk) => chunk.map_err(|error| network_error(&error, origin)),
        Err(_) => Err(request_timeout(origin)),
    }
}
