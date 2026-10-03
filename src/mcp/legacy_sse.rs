//! HTTP+SSE: one bounded GET stream and a validated same-origin POST endpoint.

use futures::StreamExt;
use reqwest::header::{ACCEPT, HeaderMap};
use reqwest::{Method, Response};
use serde_json::Value;
use sse_stream::{Error as SseError, Sse};
use tokio::time::timeout_at;
use url::Url;

use crate::error::{Error, ErrorKind};
use crate::http::client::{Redirects, request_timeout};
use crate::http::sse::{events, stream_error};
use crate::http::url_policy::UrlPolicy;
use crate::mcp::client_session::Opened;
use crate::mcp::endpoint::Endpoint;
use crate::mcp::rpc::{EventStream, protocol_error};
use crate::mcp::streamable::initialize;
use crate::mcp::wire::{Media, media, reject_auth};

/// Opens the GET endpoint, then initializes offering 2024-11-05.
pub(crate) async fn open(endpoint: &Endpoint) -> Result<Opened, Error> {
    let (transport, events) = SseTransport::connect(endpoint).await?;
    let mut opened = Opened::new(false);
    opened.sse = Some(transport);
    opened.events = Some(events);
    initialize(endpoint, &mut opened, "2024-11-05").await?;
    Ok(opened)
}

/// The checked destination for HTTP+SSE messages, separate from stream ownership.
pub(crate) struct SseTransport {
    /// Same-origin endpoint checked before any credentials are posted.
    url: Url,
}

impl SseTransport {
    /// Opens the stream and requires its first event to name the POST endpoint.
    async fn connect(endpoint: &Endpoint) -> Result<(Self, EventStream), Error> {
        let origin = endpoint.origin();
        let deadline = endpoint.bounds.deadline(false);
        let request = endpoint
            .http
            .request(Method::GET, endpoint.url.clone(), Redirects::SameOrigin)
            .headers(HeaderMap::from_iter(endpoint.headers.clone()))
            .header(ACCEPT, "text/event-stream");
        let response = endpoint.http.send(request, deadline).await?;
        check_stream(&response, &origin)?;
        let mut events = events(response, endpoint.bounds.stream(endpoint.bounds.deadline));
        let first = timeout_at(deadline, events.next())
            .await
            .map_err(|_| request_timeout(&origin))?;
        let url = post_url(first, &endpoint.url, &origin)?;
        Ok((Self { url }, events))
    }

    /// Sends one JSON-RPC message; its response arrives only on the GET stream.
    pub(crate) async fn post(
        &mut self,
        endpoint: &Endpoint,
        message: &Value,
        deadline: tokio::time::Instant,
    ) -> Result<(), Error> {
        let request = endpoint
            .http
            .request(Method::POST, self.url.clone(), Redirects::Never)
            .headers(HeaderMap::from_iter(endpoint.headers.clone()))
            .json(message);
        let response = endpoint
            .http
            .send(request, deadline.min(endpoint.bounds.deadline(false)))
            .await?;
        let origin = endpoint.origin();
        reject_auth(&response, &origin)?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::HttpStatus,
                format!("{origin} answered HTTP {status}"),
            ))
        }
    }
}

/// Only explicit transport rejection or successful non-SSE replies permit fallback.
fn check_stream(response: &Response, origin: &str) -> Result<(), Error> {
    reject_auth(response, origin)?;
    let status = response.status();
    if !status.is_success() && !matches!(status.as_u16(), 400 | 404 | 405) {
        return Err(Error::new(
            ErrorKind::HttpStatus,
            format!("{origin} answered HTTP {status}"),
        ));
    }
    if status.is_success() && matches!(media(response), Media::EventStream) {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::UnsupportedServer,
            format!("{origin} did not open an SSE stream (HTTP {status})"),
        ))
    }
}

/// The POST URL from the stream's first item, which must be an `endpoint`
/// event.
fn post_url(
    first: Option<Result<Sse, SseError>>,
    server: &Url,
    origin: &str,
) -> Result<Url, Error> {
    let data = match first {
        Some(Ok(Sse {
            event: Some(name),
            data: Some(data),
            ..
        })) if name == "endpoint" => data,
        Some(Err(error)) => return Err(stream_error(&error, origin)),
        _ => {
            return Err(protocol_error(
                origin,
                "did not name its SSE endpoint first",
            ));
        }
    };
    let url = server
        .join(data.trim())
        .map_err(|_| protocol_error(origin, "named an SSE endpoint that is not a URL"))?;
    UrlPolicy::new(server.clone()).check_endpoint(&url)?;
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://a.example";

    fn server() -> Url {
        Url::parse("https://a.example/sse").unwrap()
    }

    fn event(name: Option<&str>, data: Option<&str>) -> Sse {
        Sse {
            event: name.map(str::to_owned),
            data: data.map(str::to_owned),
            id: None,
            retry: None,
        }
    }

    fn post_kind(first: Option<Result<Sse, SseError>>) -> ErrorKind {
        post_url(first, &server(), ORIGIN).unwrap_err().kind()
    }

    #[test]
    fn the_endpoint_event_names_a_same_origin_post_url() {
        let url = post_url(
            Some(Ok(event(Some("endpoint"), Some(" /messages?s=1 ")))),
            &server(),
            ORIGIN,
        );
        assert_eq!(url.unwrap().as_str(), "https://a.example/messages?s=1");
    }

    #[test]
    fn a_stream_without_a_usable_endpoint_event_is_rejected() {
        assert_eq!(post_kind(None), ErrorKind::ProtocolError);
        assert_eq!(
            post_kind(Some(Ok(event(Some("message"), Some("/m"))))),
            ErrorKind::ProtocolError
        );
        assert_eq!(
            post_kind(Some(Ok(event(Some("endpoint"), None)))),
            ErrorKind::ProtocolError
        );
        assert_eq!(
            post_kind(Some(Ok(event(None, Some("/m"))))),
            ErrorKind::ProtocolError
        );
        assert_eq!(
            post_kind(Some(Err(SseError::InvalidLine))),
            ErrorKind::ProtocolError
        );
        assert_eq!(
            post_kind(Some(Ok(event(Some("endpoint"), Some("http://[::1"))))),
            ErrorKind::ProtocolError
        );
        assert_eq!(
            post_kind(Some(Ok(event(
                Some("endpoint"),
                Some("https://b.example/m")
            )))),
            ErrorKind::UrlRejected
        );
    }
}
