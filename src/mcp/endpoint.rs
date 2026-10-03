//! Where one session sends its requests and the limits it runs under.

use std::collections::HashMap;

use reqwest::header::{HeaderName, HeaderValue};
use url::Url;

use crate::http::client::HttpClient;
use crate::mcp::wire::Bounds;

/// A configured server, ready to connect to.
#[derive(Debug, Clone)]
pub(crate) struct Endpoint {
    /// The bounded client every request goes through.
    pub(crate) http: HttpClient,
    /// The server URL.
    pub(crate) url: Url,
    /// The static headers, expanded and checked.
    pub(crate) headers: HashMap<HeaderName, HeaderValue>,
    /// Largest decoded JSON depth.
    pub(crate) max_json_depth: u64,
    /// Largest retained tool-header metadata count.
    pub(crate) max_tools: u64,
    /// Largest retained tool definition byte count.
    pub(crate) max_tools_bytes: u64,
    /// The limits and the command deadline.
    pub(crate) bounds: Bounds,
}

impl Endpoint {
    /// The server's origin, the only part of its URL errors may name.
    pub(crate) fn origin(&self) -> String {
        self.url.origin().ascii_serialization()
    }
}
