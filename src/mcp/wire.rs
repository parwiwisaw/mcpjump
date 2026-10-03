//! Bounded HTTP messages shared by the MCP transports.

use std::collections::HashMap;
use std::time::Duration;

use futures::stream::BoxStream;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Response, StatusCode};
use serde_json::Value;
use sse_stream::{Error as SseError, Sse};
use tokio::time::Instant;

use crate::auth::challenge::Challenge;
use crate::error::{Error, ErrorKind};
use crate::http::body::{SizeLimit, read_body};
use crate::http::client::Redirects;
use crate::http::sse::{SseLimits, events};
use crate::mcp::endpoint::Endpoint;
use crate::mcp::rpc::{Message, parse, protocol_error};

/// Largest error body inspected for a JSON-RPC rejection.
const MAX_ERROR_BYTES: u64 = 64 * 1024;
/// Header carrying the initialize session, never updated by later replies.
pub(crate) const SESSION_HEADER: &str = "mcp-session-id";

/// The limits every request of one session runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bounds {
    /// Largest JSON body or SSE event.
    pub(crate) max_response_bytes: u64,
    /// Longest wait for a request other than a tool call.
    pub(crate) request_timeout: Duration,
    /// Longest wait between complete SSE lines.
    pub(crate) idle: Duration,
    /// Absolute command deadline, also the tool-call deadline.
    pub(crate) deadline: Instant,
}

impl Bounds {
    /// A tool call uses the remaining command budget; other requests get less.
    pub(crate) fn deadline(self, call: bool) -> Instant {
        if call {
            self.deadline
        } else {
            (Instant::now() + self.request_timeout).min(self.deadline)
        }
    }

    /// Limits for a stream with its own absolute deadline.
    pub(crate) fn stream(self, deadline: Instant) -> SseLimits {
        SseLimits {
            max_event_bytes: usize::try_from(self.max_response_bytes).unwrap_or(usize::MAX),
            idle: self.idle,
            deadline,
        }
    }
}

/// Content types accepted from an MCP endpoint.
pub(crate) enum Media {
    /// A single JSON body.
    Json,
    /// A bounded SSE reply stream.
    EventStream,
    /// Any unsupported content type.
    Other,
}

/// A successful POST's body, owned until the first matching reply.
pub(crate) enum Reply {
    /// A parsed JSON envelope.
    Json(Value),
    /// An owned event stream awaiting correlation.
    Stream(BoxStream<'static, Result<Sse, SseError>>),
    /// Acceptance without a reply body.
    Accepted,
}

/// A POST response and its optional initial session header.
pub(crate) struct Posted {
    /// The reply representation.
    pub(crate) reply: Reply,
    /// Session header used only by initialize.
    pub(crate) session: Option<HeaderValue>,
}

/// POSTs one message, using the existing HTTP client and bounded readers.
pub(crate) async fn post(
    endpoint: &Endpoint,
    message: &Value,
    session: Option<&HeaderValue>,
    headers: HashMap<HeaderName, String>,
    deadline: Instant,
) -> Result<Posted, Error> {
    let origin = endpoint.origin();
    let mut request = endpoint
        .http
        .request(Method::POST, endpoint.url.clone(), Redirects::SameOrigin)
        .headers(HeaderMap::from_iter(endpoint.headers.clone()))
        .header(ACCEPT, "application/json, text/event-stream")
        .json(message);
    if let Some(session) = session {
        request = request.header(SESSION_HEADER, session);
    }
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let response = endpoint.http.send(request, deadline).await?;
    reject_auth(&response, &origin)?;
    if !response.status().is_success() {
        return failure(endpoint, response, message, session.is_some(), deadline).await;
    }
    let session = response.headers().get(SESSION_HEADER).cloned();
    let reply = if response.status() == StatusCode::ACCEPTED
        || message.get("id").is_none()
        || message.get("method").is_none()
    {
        Reply::Accepted
    } else {
        match media(&response) {
            Media::EventStream => Reply::Stream(events(response, endpoint.bounds.stream(deadline))),
            Media::Json => {
                let body = read_body(
                    response,
                    SizeLimit::response(endpoint.bounds.max_response_bytes),
                    deadline,
                )
                .await?;
                Reply::Json(parse(&body, &origin, endpoint.max_json_depth)?)
            }
            Media::Other => {
                return Err(protocol_error(
                    &origin,
                    "answered a request with neither JSON nor an event stream",
                ));
            }
        }
    };
    Ok(Posted { reply, session })
}

/// Error statuses preserve the existing handshake fallback classification.
async fn failure(
    endpoint: &Endpoint,
    response: Response,
    message: &Value,
    has_session: bool,
    deadline: Instant,
) -> Result<Posted, Error> {
    let origin = endpoint.origin();
    let status = response.status();
    if status == StatusCode::NOT_FOUND && has_session {
        return Err(Error::new(
            ErrorKind::SessionLost,
            format!("{origin} no longer knows this session (HTTP 404)"),
        ));
    }
    // Large or unreadable error pages still carry an explicit HTTP rejection.
    let limit = MAX_ERROR_BYTES.min(endpoint.bounds.max_response_bytes);
    let body = read_body(response, SizeLimit::response(limit), deadline)
        .await
        .unwrap_or_default();
    let legacy = !has_session
        && [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::METHOD_NOT_ALLOWED,
        ]
        .contains(&status);
    let method = message["method"].as_str();
    if method == Some("initialize") && legacy {
        return Err(Error::new(
            ErrorKind::UnsupportedServer,
            format!("{origin} rejected initialize with HTTP {status}"),
        ));
    }
    let discover = method == Some("server/discover") && legacy;
    let rpc = error_reply(&body, message, endpoint, discover)?;
    let reply = if let Some(rpc) = rpc {
        rpc
    } else if discover {
        serde_json::json!({"jsonrpc":"2.0","id":message["id"],"error":{"code":-32600,"message":"handshake rejected"}})
    } else {
        return Err(Error::new(
            ErrorKind::HttpStatus,
            format!("{origin} answered HTTP {status}"),
        ));
    };
    Ok(Posted {
        reply: Reply::Json(reply),
        session: None,
    })
}

/// Correlates HTTP errors, re-tagging only an explicit legacy discover rejection.
fn error_reply(
    body: &[u8],
    sent: &Value,
    endpoint: &Endpoint,
    legacy_discover: bool,
) -> Result<Option<Value>, Error> {
    let origin = endpoint.origin();
    let Ok(mut value) = parse(body, &origin, endpoint.max_json_depth) else {
        return Ok(None);
    };
    if value.get("error").is_none() {
        return Ok(None);
    }
    if legacy_discover {
        value["id"] = sent["id"].clone();
    }
    match Message::read(&value, &sent["id"], &origin)? {
        Message::Error(_) => Ok(Some(value)),
        _ => Err(protocol_error(
            &origin,
            "answered a request with an uncorrelated error",
        )),
    }
}

/// Authorization diagnostics contain only the origin, status and parsed challenge.
pub(crate) fn reject_auth(response: &Response, origin: &str) -> Result<(), Error> {
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Err(Error::new(
            ErrorKind::AuthRequired,
            format!("{origin} requires authorization (HTTP {status})"),
        )
        .with_challenge(Challenge::parse(status, response.headers())));
    }
    Ok(())
}

/// Reads Content-Type ignoring case and parameters, as the previous adapter did.
pub(crate) fn media(response: &Response) -> Media {
    let value = response
        .headers()
        .get(CONTENT_TYPE)
        .map_or(&[][..], HeaderValue::as_bytes);
    let is = |prefix: &str| {
        value
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
    };
    if is("application/json") {
        Media::Json
    } else if is("text/event-stream") {
        Media::EventStream
    } else {
        Media::Other
    }
}
