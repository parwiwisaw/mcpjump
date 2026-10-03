//! MCP sessions over HTTP: the session seam, the transports behind it, and
//! the tool listing and argument checks commands run before a call.

mod client_session;
pub mod connector;
mod endpoint;
mod legacy_sse;
mod param_headers;
mod probe;
mod rpc;
pub mod session;
mod streamable;
pub mod tools;
pub mod validate;
mod wire;
