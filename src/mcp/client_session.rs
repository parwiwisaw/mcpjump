//! Sequential MCP requests and the existing session seam, without a worker.

use std::collections::HashMap;
use std::fmt::{self, Debug};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rmcp::model::ListToolsResult;
use serde_json::{Map, Value, json};
use tokio::time::Instant;

use crate::error::{Error, ErrorKind};
use crate::http::client::Redirects;
use crate::mcp::endpoint::Endpoint;
use crate::mcp::legacy_sse::SseTransport;
use crate::mcp::param_headers::{self, Annotation};
use crate::mcp::rpc::{Answer, EventStream, Message, protocol_error, receive};
use crate::mcp::session::{BoxFuture, McpSession, Tool, ToolPage, ToolResult};
use crate::mcp::streamable;
use crate::mcp::wire::{self, Posted, Reply, SESSION_HEADER};

/// Transport state after connecting, also used while performing the handshake.
pub(crate) struct Opened {
    /// Whether this is the self-contained Modern generation.
    pub(crate) modern: bool,
    /// Negotiated version; absent for the Streamable initialize POST.
    pub(crate) version: Option<&'static str>,
    /// Session header from initialize only.
    pub(crate) session: Option<HeaderValue>,
    /// HTTP+SSE's persistent GET, absent for Streamable HTTP.
    pub(crate) sse: Option<SseTransport>,
    /// Persistent GET events, detached while answering one request.
    pub(crate) events: Option<EventStream>,
    /// Set when Modern violates the independent server-request prohibition.
    pub(crate) unsolicited: bool,
    /// Next request id, saturating rather than wrapping. The command deadline
    /// bounds request count; each newly connected generation starts at zero.
    next_id: u64,
    /// Checked annotations only, bounded by the tool discovery limits.
    annotations: HashMap<String, Vec<Annotation>>,
    /// Serialized definition bytes retained across tool pages.
    tool_bytes: u64,
}

impl Debug for Opened {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Opened")
            .field("modern", &self.modern)
            .finish_non_exhaustive()
    }
}

impl Opened {
    /// Empty state for a selected generation; no background tasks are created.
    pub(crate) fn new(modern: bool) -> Self {
        Self {
            modern,
            version: modern.then_some("2026-07-28"),
            session: None,
            sse: None,
            events: None,
            unsolicited: false,
            next_id: 0,
            annotations: HashMap::new(),
            tool_bytes: 0,
        }
    }

    /// Sends a message without waiting for a JSON-RPC reply.
    pub(crate) async fn post(
        &mut self,
        endpoint: &Endpoint,
        message: &Value,
        method: &str,
        deadline: Instant,
    ) -> Result<Posted, Error> {
        if let Some(sse) = &mut self.sse {
            sse.post(endpoint, message, deadline).await?;
            return Ok(Posted {
                reply: Reply::Accepted,
                session: None,
            });
        }
        wire::post(
            endpoint,
            message,
            self.session.as_ref(),
            self.headers(message, method)?,
            deadline,
        )
        .await
    }

    /// Builds the headers owned by this generation, never echoing later ids.
    fn headers(&self, message: &Value, method: &str) -> Result<HashMap<HeaderName, String>, Error> {
        let mut headers = HashMap::new();
        if let Some(version) = &self.version {
            headers.insert(
                HeaderName::from_static("mcp-protocol-version"),
                (*version).to_owned(),
            );
        }
        if self.modern {
            headers.insert(HeaderName::from_static("mcp-method"), method.to_owned());
            if let Some(name) = message["params"]["name"].as_str() {
                headers.insert(
                    HeaderName::from_static("mcp-name"),
                    param_headers::encode(name),
                );
                if let Some(annotations) = self.annotations.get(name) {
                    headers.extend(param_headers::generate(
                        annotations,
                        &message["params"]["arguments"],
                    )?);
                }
            }
        }
        Ok(headers)
    }

    /// Generates sequential ids within the command deadline without arithmetic wrap.
    fn request_id(&mut self) -> Value {
        let id = json!(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    /// One outstanding request, with an absolute reply deadline and no cancellation POST.
    pub(crate) async fn request(
        &mut self,
        endpoint: &Endpoint,
        method: &str,
        mut params: Value,
        call: bool,
    ) -> Result<Answer, Error> {
        let id = self.request_id();
        if self.modern {
            params["_meta"] = json!({
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":{},
                "io.modelcontextprotocol/clientInfo": {"name":"mcpjump","version":env!("CARGO_PKG_VERSION")}
            });
        }
        let deadline = endpoint.bounds.deadline(call);
        let message = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        let posted = self.post(endpoint, &message, method, deadline).await?;
        if method == "initialize" && self.sse.is_none() {
            self.session = posted.session;
        }
        if self.sse.is_some() {
            let mut events = self
                .events
                .take()
                .ok_or_else(|| protocol_error(&endpoint.origin(), "closed its SSE stream"))?;
            let result = receive(&mut events, endpoint, self, &id, deadline).await;
            if result.is_ok() {
                self.events = Some(events);
            }
            return result;
        }

        match posted.reply {
            Reply::Json(value) => match Message::read(&value, &id, &endpoint.origin())? {
                Message::Result(value) => Ok(Answer::Result(value)),
                Message::Error(error) => Ok(Answer::Error(error)),
                _ => Err(protocol_error(
                    &endpoint.origin(),
                    "answered a request with another message",
                )),
            },
            Reply::Stream(mut events) => receive(&mut events, endpoint, self, &id, deadline).await,
            Reply::Accepted => Err(protocol_error(
                &endpoint.origin(),
                "accepted a request without answering",
            )),
        }
    }

    /// Remembers only the metadata needed to generate headers, with bounded retention.
    fn remember(
        &mut self,
        endpoint: &Endpoint,
        tool: &Tool,
        annotations: Vec<Annotation>,
    ) -> Result<(), Error> {
        self.tool_bytes = self
            .tool_bytes
            .saturating_add(u64::try_from(tool.definition.to_string().len()).unwrap_or(u64::MAX));
        if self.tool_bytes > endpoint.max_tools_bytes
            || (self.annotations.len() as u64 >= endpoint.max_tools
                && !self.annotations.contains_key(&tool.name))
        {
            return Err(Error::new(
                ErrorKind::ToolListLimit,
                "the server passed the tool header metadata limits",
            ));
        }
        self.annotations.insert(tool.name.clone(), annotations);
        Ok(())
    }
}

/// A session that completed its handshake on one endpoint.
#[derive(Debug)]
pub(crate) struct ClientSession {
    /// The configured server and shared HTTP client.
    endpoint: Endpoint,
    /// Negotiated transport, metadata and request counter.
    opened: Opened,
    /// Whether the single allowed session recovery was used.
    reopened: bool,
}

impl ClientSession {
    /// Wraps the negotiated transport without spawning a dispatcher.
    pub(crate) const fn new(endpoint: Endpoint, opened: Opened) -> Self {
        Self {
            endpoint,
            opened,
            reopened: false,
        }
    }

    /// Reopens Legacy Streamable once after an explicit pre-execution 404.
    async fn request(&mut self, method: &str, params: Value, call: bool) -> Result<Value, Error> {
        let first = self
            .opened
            .request(&self.endpoint, method, params.clone(), call)
            .await;
        let outcome = match first {
            Err(error) if error.kind() == ErrorKind::SessionLost && !self.reopened => {
                self.reopened = true;
                let opened = streamable::open(&self.endpoint, false).await?;
                close(&self.endpoint, std::mem::replace(&mut self.opened, opened)).await;
                self.opened
                    .request(&self.endpoint, method, params, call)
                    .await
            }
            other => other,
        };
        let result = outcome.and_then(|message| match message {
            Answer::Result(value) => Ok(value),
            Answer::Error(data) => Err(rpc_error(&data, &self.endpoint.origin())),
        });
        if call && !self.opened.unsolicited {
            result.map_err(call_error)
        } else {
            result
        }
    }

    /// Decodes the list model and filters Modern's invalid header annotations.
    fn tool_page(&mut self, value: Value) -> Result<ToolPage, Error> {
        let definitions = value["tools"].as_array().ok_or_else(|| {
            protocol_error(
                &self.endpoint.origin(),
                "answered tools/list with another result",
            )
        })?;
        let received_count = u64::try_from(definitions.len()).unwrap_or(u64::MAX);
        let received_bytes = definitions.iter().fold(0_u64, |bytes, definition| {
            bytes.saturating_add(u64::try_from(definition.to_string().len()).unwrap_or(u64::MAX))
        });
        let list: ListToolsResult = serde_json::from_value(value).map_err(|_| {
            protocol_error(
                &self.endpoint.origin(),
                "answered tools/list with another result",
            )
        })?;
        let mut tools = Vec::new();
        for tool in list.tools {
            let definition = json!(tool);
            let tool = Tool {
                name: tool.name.into_owned(),
                definition,
            };
            if self.opened.modern {
                let Some(annotations) = param_headers::annotations(&tool.definition["inputSchema"])
                else {
                    continue;
                };
                self.opened.remember(&self.endpoint, &tool, annotations)?;
            }
            tools.push(tool);
        }
        Ok(ToolPage {
            tools,
            received_count,
            received_bytes,
            next_cursor: list.next_cursor,
        })
    }
}

impl McpSession for ClientSession {
    fn list_tools_page(
        &mut self,
        cursor: Option<String>,
    ) -> BoxFuture<'_, Result<ToolPage, Error>> {
        Box::pin(async move {
            let params = cursor.map_or_else(|| json!({}), |cursor| json!({"cursor":cursor}));
            let result = self.request("tools/list", params, false).await?;
            self.tool_page(result)
        })
    }

    fn call_tool(
        &mut self,
        name: &str,
        arguments: Map<String, Value>,
    ) -> BoxFuture<'_, Result<ToolResult, Error>> {
        let params = json!({"name":name,"arguments":arguments});
        Box::pin(async move {
            let result = self.request("tools/call", params, true).await?;
            call_result(result, &self.endpoint.origin())
        })
    }

    fn close(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            close(&self.endpoint, self.opened).await;
        })
    }
}

/// Dropping SSE releases its stream; DELETE is best effort for an initialize session.
async fn close(endpoint: &Endpoint, opened: Opened) {
    if let Some(session) = opened.session {
        let request = endpoint
            .http
            .request(
                reqwest::Method::DELETE,
                endpoint.url.clone(),
                Redirects::Never,
            )
            .headers(HeaderMap::from_iter(endpoint.headers.clone()))
            .header(SESSION_HEADER, session);
        let request = opened
            .version
            .into_iter()
            .fold(request, |request, version| {
                request.header("mcp-protocol-version", version)
            });
        let _closed = endpoint
            .http
            .send(request, endpoint.bounds.deadline(false))
            .await;
    }
}

/// RPC diagnostics expose the code, never the server's text or data.
fn rpc_error(data: &rmcp::model::ErrorData, origin: &str) -> Error {
    let kind = if data.code.0 == -32602 {
        ErrorKind::InvalidParams
    } else {
        ErrorKind::ServerError
    };
    Error::new(
        kind,
        format!("{origin} answered with JSON-RPC error {}", data.code.0),
    )
}

/// Only explicit rejections or bounded-response failures prove a call's outcome.
fn call_error(cause: Error) -> Error {
    match cause.kind() {
        ErrorKind::AuthRequired
        | ErrorKind::ConnectTimeout
        | ErrorKind::SessionLost
        | ErrorKind::InvalidParams
        | ErrorKind::ResponseTooLarge
        | ErrorKind::ServerError => cause,
        _ => Error::new(
            ErrorKind::DeliveryUnknown,
            format!("the tool call may or may not have run: {}", cause.message()),
        ),
    }
}

/// Keeps the original result object, including unknown and null fields.
fn call_result(value: Value, origin: &str) -> Result<ToolResult, Error> {
    if value["content"].is_array() {
        return Ok(ToolResult {
            is_error: value["isError"] == true,
            value,
        });
    }
    if value.get("task").is_some() || value["resultType"] == "input_required" {
        return Err(Error::new(
            ErrorKind::UnsupportedFeature,
            format!("{origin} asked for input or started a task, which mcpjump does not support"),
        ));
    }
    Err(protocol_error(
        origin,
        "answered tools/call with another result",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ids start at zero and never wrap; debug output omits even an issued session secret.
    #[test]
    fn request_ids_never_wrap_and_debug_omits_transport_secrets() {
        let mut opened = Opened::new(true);
        assert_eq!(opened.request_id(), json!(0));
        assert_eq!(opened.request_id(), json!(1));
        opened.next_id = u64::MAX;
        assert_eq!(opened.request_id(), json!(u64::MAX));
        assert_eq!(opened.next_id, u64::MAX);
        opened.session = Some(HeaderValue::from_static("server secret"));
        assert_eq!(format!("{opened:?}"), "Opened { modern: true, .. }");
    }

    /// The unchanged ambiguous-delivery classification preserves explicit rejections.
    #[test]
    fn call_failures_preserve_only_known_outcomes() {
        for kind in [
            ErrorKind::AuthRequired,
            ErrorKind::ConnectTimeout,
            ErrorKind::SessionLost,
            ErrorKind::InvalidParams,
            ErrorKind::ResponseTooLarge,
            ErrorKind::ServerError,
        ] {
            assert_eq!(call_error(Error::new(kind, "failure")).kind(), kind);
        }
        assert_eq!(
            call_error(Error::new(ErrorKind::Network, "reset")).kind(),
            ErrorKind::DeliveryUnknown
        );
    }
}
