//! The connection seam: turns a configured server into an open
//! [`McpSession`].

use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Duration;

use reqwest::header::{HeaderName, HeaderValue};
use tokio::time::Instant;
use url::Url;

use crate::config::limits::Limits;
use crate::config::model::{Generation, Transport};
use crate::error::{Error, ErrorKind};
use crate::http::client::HttpClient;
use crate::mcp::client_session::ClientSession;
use crate::mcp::endpoint::Endpoint;
use crate::mcp::probe::probe;
use crate::mcp::session::{BoxFuture, McpSession};
use crate::mcp::wire::Bounds;

/// A generic User-Agent: the product and version, nothing about the user.
pub(crate) const USER_AGENT: &str = concat!("mcpjump/", env!("CARGO_PKG_VERSION"));

/// What to connect to, and under which limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The server URL.
    pub url: Url,
    /// The configured transport.
    pub transport: Transport,
    /// The generation that answered last time, tried first.
    pub generation: Option<Generation>,
    /// The static headers, `${VAR}` already expanded.
    pub headers: Vec<(String, String)>,
    /// The limits in force.
    pub limits: Limits,
    /// When the whole command must end.
    pub deadline: Instant,
}

/// An open session and the generation it speaks.
#[derive(Debug)]
pub struct Connection {
    /// The session.
    pub session: Box<dyn McpSession>,
    /// The generation that answered, saved for next time.
    pub generation: Generation,
}

/// Opens sessions. The composition root picks the implementation; tests
/// use a fake.
pub trait SessionConnector: Debug + Sync {
    /// Connects to `target` and completes the MCP handshake.
    ///
    /// # Errors
    /// Network, auth, protocol and limit errors, or `unsupported_server`
    /// when no generation answered.
    fn connect(&self, target: Target) -> BoxFuture<'_, Result<Connection, Error>>;
}

/// The real connector: HTTP through the bounded client, sessions through
/// the in-house sequential MCP client.
#[derive(Debug, Default)]
pub struct HttpConnector;

impl SessionConnector for HttpConnector {
    fn connect(&self, target: Target) -> BoxFuture<'_, Result<Connection, Error>> {
        Box::pin(async move {
            let endpoint = endpoint(&target)?;
            let (opened, generation) =
                probe(&endpoint, target.transport, target.generation).await?;
            let session: Box<dyn McpSession> = Box::new(ClientSession::new(endpoint, opened));
            Ok(Connection {
                session,
                generation,
            })
        })
    }
}

fn endpoint(target: &Target) -> Result<Endpoint, Error> {
    let limits = &target.limits;
    let bounds = Bounds {
        max_response_bytes: limits.max_response_bytes,
        request_timeout: Duration::from_secs(limits.request_timeout_secs),
        idle: Duration::from_secs(limits.stream_idle_secs),
        deadline: target.deadline,
    };
    HttpClient::new(Duration::from_secs(limits.connect_timeout_secs), USER_AGENT).and_then(|http| {
        headers(&target.headers).map(|headers| Endpoint {
            http,
            url: target.url.clone(),
            headers,
            bounds,
            max_json_depth: limits.max_json_depth,
            max_tools: limits.max_tools,
            max_tools_bytes: limits.max_tools_bytes,
        })
    })
}

/// Converts the expanded headers. A value can turn invalid only through
/// `${VAR}` expansion; the error names the header, never its value.
fn headers(pairs: &[(String, String)]) -> Result<HashMap<HeaderName, HeaderValue>, Error> {
    pairs
        .iter()
        .map(|(name, value)| {
            HeaderName::try_from(name.as_str())
                .ok()
                .zip(HeaderValue::try_from(value.as_str()).ok())
                .ok_or_else(|| invalid_header(name))
        })
        .collect()
}

fn invalid_header(name: &str) -> Error {
    Error::new(
        ErrorKind::InvalidHeader,
        format!("header {name} is not a valid HTTP header after ${{VAR}} expansion"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(name.to_owned(), value.to_owned())]
    }

    #[test]
    fn expanded_headers_must_still_be_valid() {
        let good = headers(&pairs("X-Team", "blue")).unwrap();
        assert_eq!(good[&HeaderName::from_static("x-team")], "blue");
        let bad_value = headers(&pairs("X-Team", "a\nb")).unwrap_err();
        assert_eq!(bad_value.kind(), ErrorKind::InvalidHeader);
        assert!(!bad_value.message().contains("a\nb"));
        let bad_name = headers(&pairs("bad name", "v")).unwrap_err();
        assert_eq!(bad_name.kind(), ErrorKind::InvalidHeader);
    }
}
