//! The real connector, pointed at a fixture server.

use mcpjump::config::limits::Limits;
use mcpjump::config::model::{Generation, Transport};
use mcpjump::error::Error;
use mcpjump::mcp::connector::{Connection, HttpConnector, SessionConnector, Target};
use serde_json::{Map, Value, json};
use url::Url;

use crate::support::http::after;

/// A target with the default limits and a 20 second deadline.
pub(crate) fn target(url: Url, transport: Transport, generation: Option<Generation>) -> Target {
    Target {
        url,
        transport,
        generation,
        headers: Vec::new(),
        limits: Limits::default(),
        deadline: after(20_000),
    }
}

/// An HTTP target with no saved generation.
pub(crate) fn http(url: Url) -> Target {
    target(url, Transport::Http, None)
}

/// Connects with [`HttpConnector`].
pub(crate) async fn connect(target: Target) -> Result<Connection, Error> {
    HttpConnector.connect(target).await
}

/// The kind of the error `target` fails to connect with.
pub(crate) async fn connect_error(target: Target) -> &'static str {
    connect(target).await.unwrap_err().kind().as_str()
}

/// `{"n": 1}`.
pub(crate) fn arguments() -> Map<String, Value> {
    json!({"n": 1}).as_object().unwrap().clone()
}
