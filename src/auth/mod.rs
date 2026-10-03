//! OAuth 2.1 for MCP servers: discovery, client registration, the browser
//! login, and token refresh.

pub(crate) mod callback;
pub mod challenge;
pub(crate) mod discovery;
pub(crate) mod flow;
pub(crate) mod http;
pub(crate) mod loopback;
pub(crate) mod paste;
pub(crate) mod pkce;
pub(crate) mod refresh;
pub(crate) mod registration;
pub(crate) mod token;
pub(crate) mod vault;
