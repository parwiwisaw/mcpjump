//! Bounded HTTP: the client, size-bounded bodies, bounded SSE framing, and the
//! rules for URLs a server advertises.

pub mod body;
pub mod client;
pub mod sse;
pub mod url_policy;
