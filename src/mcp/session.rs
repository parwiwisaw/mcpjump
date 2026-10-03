//! The session seam: what commands need from a connected MCP server.

use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;

use serde_json::{Map, Value};

use crate::error::Error;

/// A boxed, sendable future: the return type of the async seam methods,
/// which must stay `dyn`-compatible.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One tool as the server listed it.
#[derive(Debug, Clone, PartialEq)]
pub struct Tool {
    /// The tool name, not yet checked against the naming rule.
    pub name: String,
    /// The whole tool definition as JSON, `inputSchema` included.
    pub definition: Value,
}

/// One page of `tools/list`.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolPage {
    /// The tools retained after transport-specific filtering.
    pub tools: Vec<Tool>,
    /// All definitions received on this page, before filtering.
    pub received_count: u64,
    /// Serialized raw definition bytes, excluding the response envelope.
    pub received_bytes: u64,
    /// The cursor for the next page, if there is one.
    pub next_cursor: Option<String>,
}

/// The result of `tools/call`.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolResult {
    /// The `CallToolResult` as JSON.
    pub value: Value,
    /// Whether the tool reported `isError: true`.
    pub is_error: bool,
}

/// A connected MCP server. Every method runs under the deadline the session
/// was opened with.
pub trait McpSession: Debug + Send {
    /// Fetches one page of tools.
    ///
    /// # Errors
    /// Network, protocol and limit errors.
    fn list_tools_page(&mut self, cursor: Option<String>)
    -> BoxFuture<'_, Result<ToolPage, Error>>;

    /// Calls a tool once. Never retried after the request may have reached
    /// the server.
    ///
    /// # Errors
    /// `delivery_unknown` when the call may or may not have run; otherwise
    /// the error that stopped it before it ran.
    fn call_tool(
        &mut self,
        name: &str,
        arguments: Map<String, Value>,
    ) -> BoxFuture<'_, Result<ToolResult, Error>>;

    /// Ends the session, best effort and bounded.
    fn close(self: Box<Self>) -> BoxFuture<'static, ()>;
}
