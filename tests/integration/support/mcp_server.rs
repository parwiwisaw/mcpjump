//! Scripted MCP servers: Streamable HTTP on `/mcp`, and the 2024-11-05
//! HTTP+SSE transport on `/sse` with posts to `/messages`. Each answers a
//! message with what the test's script returns and logs what it received.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use futures::stream;
use rmcp::model::{
    CallToolResult, ContentBlock, DiscoverResult, ErrorCode, ErrorData, InitializeResult,
    JsonObject, ListToolsResult, ProtocolVersion, RequestId, ServerCapabilities,
    ServerJsonRpcMessage, ServerResult, Tool, ToolsCapability,
};
use serde_json::Value;
use tokio::sync::mpsc;
use url::Url;

use crate::support::http::serve;

/// The session a Legacy Streamable fixture hands out.
pub(crate) const SESSION: &str = "s1";

/// The endpoint event an SSE fixture sends first.
pub(crate) const ENDPOINT: &str = "event: endpoint\ndata: /messages?s=1\n\n";

/// One message the server received.
#[derive(Debug, Clone)]
pub(crate) struct Received {
    /// The method, or `response` for the client's answer to a request.
    pub(crate) method: String,
    pub(crate) id: Option<RequestId>,
    pub(crate) params: Value,
    pub(crate) session: Option<String>,
    /// The whole message, for a client answer's `result` or `error`.
    pub(crate) message: Value,
    pub(crate) headers: HeaderMap,
}

/// What a fixture received, in order: the method, `@session` when one was
/// sent, and `delete@session` for a session delete.
pub(crate) type Log = Arc<Mutex<Vec<String>>>;

/// What `log` holds so far.
pub(crate) fn entries(log: &Log) -> Vec<String> {
    log.lock().unwrap().clone()
}

/// Answers one POST to a Streamable HTTP fixture.
pub(crate) type Script = Arc<dyn Fn(&Received) -> Response + Send + Sync>;

/// Answers one POST to an SSE fixture: the POST's status and the frames to
/// push onto the stream.
pub(crate) type SseScript = Arc<dyn Fn(&Received) -> (StatusCode, Vec<String>) + Send + Sync>;

struct Streamable {
    script: Script,
    log: Log,
}

struct SseFixture {
    first: String,
    script: SseScript,
    log: Log,
    stream: Mutex<Option<mpsc::UnboundedSender<String>>>,
}

/// Serves `script` on `/mcp`; returns the URL of `/mcp` and the log.
pub(crate) async fn streamable(script: Script) -> (Url, Log) {
    let log = Log::default();
    let state = Arc::new(Streamable {
        script,
        log: Arc::clone(&log),
    });
    let router = Router::new()
        .route("/mcp", post(on_post).delete(on_delete))
        .with_state(state);
    (serve(router).await.join("mcp").unwrap(), log)
}

/// Serves an SSE fixture whose stream starts with `first`; returns the URL
/// of `/sse` and the log.
pub(crate) async fn sse(first: &str, script: SseScript) -> (Url, Log) {
    let log = Log::default();
    let state = Arc::new(SseFixture {
        first: first.to_owned(),
        script,
        log: Arc::clone(&log),
        stream: Mutex::new(None),
    });
    let router = Router::new()
        .route("/sse", get(on_stream))
        .route("/messages", post(on_message))
        .with_state(state);
    (serve(router).await.join("sse").unwrap(), log)
}

async fn on_post(
    State(fixture): State<Arc<Streamable>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let received = parse(&headers, &body);
    fixture.log.lock().unwrap().push(label(&received));
    (fixture.script)(&received)
}

/// Logs `delete@session`, plus ` x-key=value` when that header was sent.
async fn on_delete(State(fixture): State<Arc<Streamable>>, headers: HeaderMap) -> StatusCode {
    let session = session(&headers).unwrap_or_default();
    let key = headers
        .get("x-key")
        .map(|value| format!(" x-key={}", value.to_str().unwrap()))
        .unwrap_or_default();
    fixture
        .log
        .lock()
        .unwrap()
        .push(format!("delete@{session}{key}"));
    StatusCode::OK
}

async fn on_stream(State(fixture): State<Arc<SseFixture>>) -> Response {
    let (sender, receiver) = mpsc::unbounded_channel();
    sender.send(fixture.first.clone()).unwrap();
    *fixture.stream.lock().unwrap() = Some(sender);
    let frames = stream::unfold(receiver, |mut receiver| async move {
        let frame = receiver.recv().await?;
        Some((Ok::<_, Infallible>(Bytes::from(frame)), receiver))
    });
    event_stream(Body::from_stream(frames))
}

async fn on_message(
    State(fixture): State<Arc<SseFixture>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let received = parse(&headers, &body);
    fixture.log.lock().unwrap().push(label(&received));
    let (status, frames) = (fixture.script)(&received);
    let stream = fixture.stream.lock().unwrap();
    for frame in frames {
        let _ = stream.as_ref().map(|sender| sender.send(frame));
    }
    status
}

fn parse(headers: &HeaderMap, body: &[u8]) -> Received {
    let value: Value = serde_json::from_slice(body).unwrap();
    Received {
        method: value["method"].as_str().unwrap_or("response").to_owned(),
        id: value
            .get("id")
            .map(|id| serde_json::from_value(id.clone()).unwrap()),
        params: value.get("params").cloned().unwrap_or(Value::Null),
        session: session(headers),
        message: value.clone(),
        headers: headers.clone(),
    }
}

fn session(headers: &HeaderMap) -> Option<String> {
    headers
        .get("mcp-session-id")
        .map(|value| value.to_str().unwrap().to_owned())
}

fn label(received: &Received) -> String {
    match &received.session {
        Some(session) => format!("{}@{session}", received.method),
        None => received.method.clone(),
    }
}

/// `result` as the answer to `received`.
pub(crate) fn reply(received: &Received, result: ServerResult) -> ServerJsonRpcMessage {
    ServerJsonRpcMessage::response(result, received.id.clone().unwrap())
}

/// One JSON message.
pub(crate) fn json(message: &ServerJsonRpcMessage) -> Response {
    raw_json(serde_json::to_string(message).unwrap())
}

/// A JSON body as given.
pub(crate) fn raw_json(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// An event stream of `messages`, one event each.
pub(crate) fn events(messages: &[ServerJsonRpcMessage]) -> Response {
    let body: String = messages.iter().map(frame).collect();
    event_stream(Body::from(body))
}

/// A body served as an event stream.
pub(crate) fn event_stream(body: Body) -> Response {
    ([(header::CONTENT_TYPE, "text/event-stream")], body).into_response()
}

/// `message` as one SSE event.
pub(crate) fn frame(message: &ServerJsonRpcMessage) -> String {
    format!("data: {}\n\n", serde_json::to_string(message).unwrap())
}

/// `response` with the fixture's session header.
pub(crate) fn with_session(mut response: Response, session: &'static str) -> Response {
    response
        .headers_mut()
        .insert("mcp-session-id", session.parse().unwrap());
    response
}

/// A `tools/list` answer holding `tools`.
pub(crate) fn tools_reply(received: &Received, tools: Vec<Tool>) -> ServerJsonRpcMessage {
    reply(
        received,
        ServerResult::from(ListToolsResult::with_all_items(tools)),
    )
}

/// A JSON-RPC error with `code` and text a test can look for.
pub(crate) fn rpc_error(received: &Received, code: ErrorCode) -> ServerJsonRpcMessage {
    let data = ErrorData::new(code, "server secret", None);
    ServerJsonRpcMessage::error(data, received.id.clone())
}

/// The standard answer to `received`, if it is a request.
pub(crate) fn answer(received: &Received) -> Option<ServerJsonRpcMessage> {
    answer_with_version(received, ProtocolVersion::V_2025_06_18)
}

/// The standard answer, negotiating the version selected by the test.
pub(crate) fn answer_with_version(
    received: &Received,
    version: ProtocolVersion,
) -> Option<ServerJsonRpcMessage> {
    let result = match received.method.as_str() {
        "server/discover" => discover(),
        "initialize" => initialize(version),
        "tools/list" => return Some(tools_reply(received, vec![echo_tool()])),
        "tools/call" => echo(&received.params),
        _ => return None,
    };
    Some(reply(received, result))
}

/// A Modern server with one tool, `echo`.
pub(crate) fn modern(received: &Received) -> Response {
    answer(received).map_or_else(
        || StatusCode::ACCEPTED.into_response(),
        |message| json(&message),
    )
}

/// A Legacy Streamable server: `server/discover` gets HTTP 400, `initialize`
/// hands out [`SESSION`].
pub(crate) fn legacy(received: &Received) -> Response {
    match received.method.as_str() {
        "server/discover" => StatusCode::BAD_REQUEST.into_response(),
        "initialize" => with_session(modern(received), SESSION),
        _ => modern(received),
    }
}

/// An SSE server: each answer goes onto the stream.
pub(crate) fn sse_answer(received: &Received) -> (StatusCode, Vec<String>) {
    let frames = answer(received).iter().map(frame).collect();
    (StatusCode::ACCEPTED, frames)
}

fn discover() -> ServerResult {
    ServerResult::from(DiscoverResult::new(
        vec![ProtocolVersion::V_2026_07_28],
        capabilities(),
    ))
}

/// An initialize result with the test's negotiated version.
fn initialize(version: ProtocolVersion) -> ServerResult {
    ServerResult::from(InitializeResult::new(capabilities()).with_protocol_version(version))
}

fn capabilities() -> ServerCapabilities {
    let mut capabilities = ServerCapabilities::default();
    capabilities.tools = Some(ToolsCapability::default());
    capabilities
}

fn echo_tool() -> Tool {
    Tool::new("echo", "Echoes its arguments", JsonObject::new())
}

/// A text result holding the call's arguments.
fn echo(params: &Value) -> ServerResult {
    let text = params["arguments"].to_string();
    ServerResult::from(CallToolResult::success(vec![ContentBlock::text(text)]))
}
