//! Streamable HTTP answers the connector refuses or recovers from.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures::stream;
use mcpjump::config::model::{Generation, Transport};
use mcpjump::mcp::connector::Connection;
use rmcp::model::{
    CustomRequest, ErrorCode, JsonObject, PingRequest, RequestId, ServerJsonRpcMessage,
    ServerNotification, ServerRequest, Tool, ToolListChangedNotification,
};
use serde_json::{Map, Value, json};

use crate::support::http::closed_port;
use crate::support::mcp_client::{arguments, connect, connect_error, http, target};
use crate::support::mcp_server::{
    Received, SESSION, answer, entries, event_stream, events, json, legacy, modern, raw_json,
    rpc_error, streamable, tools_reply, with_session,
};

/// Answers `tools/list` and `tools/call` with `on_tools`, everything else
/// as `base` does.
async fn serve_with(
    base: fn(&Received) -> Response,
    on_tools: impl Fn(&Received) -> Response + Send + Sync + 'static,
) -> Connection {
    let (url, _log) = streamable(Arc::new(move |received: &Received| {
        if received.method.starts_with("tools/") {
            on_tools(received)
        } else {
            base(received)
        }
    }))
    .await;
    connect(http(url)).await.unwrap()
}

async fn list_error(connection: &mut Connection) -> &'static str {
    let error = connection.session.list_tools_page(None).await.unwrap_err();
    assert!(!error.message().contains("secret"));
    error.kind().as_str()
}

fn standard(received: &Received) -> ServerJsonRpcMessage {
    answer(received).unwrap()
}

fn ping() -> ServerJsonRpcMessage {
    ServerJsonRpcMessage::request(
        ServerRequest::PingRequest(PingRequest::default()),
        RequestId::Number(90),
    )
}

#[tokio::test]
async fn http_401_is_auth_required_and_ends_the_probe() {
    let (url, log) = streamable(Arc::new(|_: &Received| {
        StatusCode::UNAUTHORIZED.into_response()
    }))
    .await;
    assert_eq!(connect_error(http(url)).await, "auth_required");
    assert_eq!(entries(&log), ["server/discover"]);
}

#[tokio::test]
async fn answers_may_arrive_as_event_streams_with_notifications() {
    let mut connection = serve_with(modern, |received| {
        let changed = ServerJsonRpcMessage::notification(
            ServerNotification::ToolListChangedNotification(ToolListChangedNotification::default()),
        );
        events(&[changed, standard(received)])
    })
    .await;
    let page = connection.session.list_tools_page(None).await.unwrap();
    assert_eq!(page.tools[0].name, "echo");
    let result = connection
        .session
        .call_tool("echo", arguments())
        .await
        .unwrap();
    assert_eq!(result.value["content"][0]["text"], r#"{"n":1}"#);
}

fn big_tool() -> Tool {
    Tool::new("big", "x".repeat(2 * 1024), JsonObject::new())
}

#[tokio::test]
async fn an_answer_over_max_response_bytes_is_refused() {
    for as_stream in [false, true] {
        let (url, _log) = streamable(Arc::new(move |received: &Received| {
            if received.method != "tools/list" {
                return modern(received);
            }
            let message = tools_reply(received, vec![big_tool()]);
            if as_stream {
                events(&[message])
            } else {
                json(&message)
            }
        }))
        .await;
        let mut small = http(url);
        small.limits.max_response_bytes = 1024;
        let mut connection = connect(small).await.unwrap();
        assert_eq!(list_error(&mut connection).await, "response_too_large");
    }
}

#[tokio::test]
async fn an_answer_that_is_not_json_rpc_is_a_protocol_error() {
    let not_rpc = |_: &Received| raw_json("{}".to_owned());
    assert_eq!(
        list_error(&mut serve_with(modern, not_rpc).await).await,
        "protocol_error"
    );
    let text = |_: &Received| "hello".into_response();
    assert_eq!(
        list_error(&mut serve_with(modern, text).await).await,
        "protocol_error"
    );
}

#[tokio::test]
async fn an_error_status_names_its_json_rpc_code_or_the_status() {
    let with_code = |code: ErrorCode| {
        move |received: &Received| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                json(&rpc_error(received, code)),
            )
                .into_response()
        }
    };
    let invalid = with_code(ErrorCode::INVALID_PARAMS);
    assert_eq!(
        list_error(&mut serve_with(modern, invalid).await).await,
        "invalid_params"
    );
    let internal = with_code(ErrorCode::INTERNAL_ERROR);
    assert_eq!(
        list_error(&mut serve_with(modern, internal).await).await,
        "server_error"
    );
    let plain = |_: &Received| StatusCode::INTERNAL_SERVER_ERROR.into_response();
    assert_eq!(
        list_error(&mut serve_with(modern, plain).await).await,
        "http_status"
    );
}

/// A body that breaks after its first bytes.
fn cut_short() -> Response {
    let parts = [
        Ok(Bytes::from("data: {")),
        Err(std::io::Error::other("cut")),
    ];
    event_stream(Body::from_stream(stream::iter(parts)))
}

#[tokio::test]
async fn a_call_that_fails_without_an_answer_is_delivery_unknown_and_not_retried() {
    let failures: [fn() -> Response; 2] = [|| StatusCode::BAD_GATEWAY.into_response(), cut_short];
    for failure in failures {
        let (url, log) = streamable(Arc::new(move |received: &Received| {
            match received.method.as_str() {
                "tools/call" => failure(),
                _ => modern(received),
            }
        }))
        .await;
        let mut connection = connect(http(url)).await.unwrap();
        let error = connection
            .session
            .call_tool("echo", arguments())
            .await
            .unwrap_err();
        assert_eq!(error.kind().as_str(), "delivery_unknown");
        let calls = entries(&log)
            .iter()
            .filter(|entry| *entry == "tools/call")
            .count();
        assert_eq!(calls, 1);
    }
}

#[tokio::test]
async fn a_json_answer_for_another_request_is_a_protocol_error() {
    let wrong_id = |received: &Received| {
        let mut other = received.clone();
        other.id = Some(RequestId::Number(999));
        json(&standard(&other))
    };
    assert_eq!(
        list_error(&mut serve_with(modern, wrong_id).await).await,
        "protocol_error"
    );
    let notification = |_: &Received| {
        json(&ServerJsonRpcMessage::notification(
            ServerNotification::ToolListChangedNotification(ToolListChangedNotification::default()),
        ))
    };
    assert_eq!(
        list_error(&mut serve_with(modern, notification).await).await,
        "protocol_error"
    );
}

#[tokio::test]
async fn modern_requests_carry_the_version_method_and_name() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&seen);
    let (url, _log) = streamable(Arc::new(move |received: &Received| {
        keep.lock().unwrap().push(received.clone());
        modern(received)
    }))
    .await;
    let mut connection = connect(http(url)).await.unwrap();
    connection
        .session
        .call_tool("echo", arguments())
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    for received in seen.iter() {
        let header = |name: &str| received.headers[name].to_str().unwrap().to_owned();
        assert_eq!(header("mcp-protocol-version"), "2026-07-28");
        assert_eq!(header("mcp-method"), received.method);
        let meta = &received.params["_meta"];
        assert_eq!(
            meta["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        assert!(meta["io.modelcontextprotocol/clientCapabilities"].is_object());
    }
    assert_eq!(seen[1].headers["mcp-name"], "echo");
}

#[tokio::test]
async fn a_modern_server_request_is_refused_and_reported() {
    let mut connection = serve_with(modern, |received| events(&[ping(), standard(received)])).await;
    assert_eq!(list_error(&mut connection).await, "protocol_error");
}

#[tokio::test]
async fn a_legacy_server_may_ping_and_other_requests_are_refused() {
    let answers = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&answers);
    let (url, _log) = streamable(Arc::new(move |received: &Received| {
        if received.method == "response" {
            keep.lock().unwrap().push(received.message.clone());
        }
        if received.method != "tools/list" {
            return legacy(received);
        }
        let custom = ServerJsonRpcMessage::request(
            ServerRequest::CustomRequest(CustomRequest::new("x/ask", None)),
            RequestId::Number(91),
        );
        events(&[ping(), custom, standard(received)])
    }))
    .await;
    let mut connection = connect(http(url)).await.unwrap();
    connection.session.list_tools_page(None).await.unwrap();
    connection.session.close().await;
    let answers = answers.lock().unwrap();
    assert_eq!(answers[0]["id"], 90);
    assert_eq!(answers[0]["result"], json!({}));
    assert_eq!(answers[1]["id"], 91);
    assert_eq!(answers[1]["error"]["code"], -32601);
}

/// A legacy server that forgets each session after `lives` requests on
/// it; `initialize` may fail after the first.
async fn forgetful(
    lives: usize,
    reinit: StatusCode,
) -> (Connection, crate::support::mcp_server::Log) {
    let inits = AtomicUsize::new(0);
    let (url, log) = streamable(Arc::new(move |received: &Received| {
        match received.method.as_str() {
            "initialize" if inits.fetch_add(1, Ordering::SeqCst) > 0 => {
                if reinit.is_success() {
                    with_session(json(&standard(received)), "s2")
                } else {
                    reinit.into_response()
                }
            }
            "tools/list" if received.session.as_deref() == Some(SESSION) || lives == 0 => {
                StatusCode::NOT_FOUND.into_response()
            }
            _ => legacy(received),
        }
    }))
    .await;
    let saved = target(url, Transport::Http, Some(Generation::LegacyStreamable));
    (connect(saved).await.unwrap(), log)
}

#[tokio::test]
async fn a_forgotten_legacy_session_is_opened_again_once() {
    let (mut connection, log) = forgetful(1, StatusCode::OK).await;
    connection.session.list_tools_page(None).await.unwrap();
    let log = entries(&log);
    assert!(log.contains(&"tools/list@s1".to_owned()));
    assert!(log.contains(&"tools/list@s2".to_owned()));
    let (mut again, _log) = forgetful(0, StatusCode::OK).await;
    assert_eq!(list_error(&mut again).await, "session_lost");
    let (mut broken, _log) = forgetful(1, StatusCode::INTERNAL_SERVER_ERROR).await;
    assert_eq!(list_error(&mut broken).await, "http_status");
}

#[tokio::test]
async fn mirrored_param_headers_are_bounded() {
    let schema = json!({"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}});
    let (url, log) = streamable(Arc::new(move |received: &Received| {
        let schema: JsonObject = schema.as_object().unwrap().clone();
        match received.method.as_str() {
            "tools/list" => json(&tools_reply(
                received,
                vec![Tool::new("geo", "Geo", schema)],
            )),
            _ => modern(received),
        }
    }))
    .await;
    let mut connection = connect(http(url)).await.unwrap();
    connection.session.list_tools_page(None).await.unwrap();
    let mut oversized = Map::new();
    oversized.insert("region".to_owned(), Value::String("a".repeat(9 * 1024)));
    let error = connection
        .session
        .call_tool("geo", oversized)
        .await
        .unwrap_err();
    assert_eq!(error.kind().as_str(), "invalid_params");
    assert!(!entries(&log).contains(&"tools/call".to_owned()));
}

#[tokio::test]
async fn an_expanded_header_must_be_valid() {
    let (url, _log) = streamable(Arc::new(modern)).await;
    let mut bad = http(url);
    bad.headers = vec![("X-Key".to_owned(), "a\nb".to_owned())];
    assert_eq!(connect_error(bad).await, "invalid_header");
}

#[tokio::test]
async fn a_stream_that_ends_early_is_reported() {
    let body = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n";
    let mut connection =
        serve_with(modern, move |_| event_stream(axum::body::Body::from(body))).await;
    assert_eq!(list_error(&mut connection).await, "protocol_error");
}

#[tokio::test]
async fn a_server_that_is_not_listening_is_a_network_error() {
    let url = closed_port().await.join("mcp").unwrap();
    assert_eq!(connect_error(http(url)).await, "network");
}

#[tokio::test]
async fn a_legacy_session_request_with_an_error_status_is_not_a_legacy_signal() {
    let plain = |_: &Received| StatusCode::INTERNAL_SERVER_ERROR.into_response();
    assert_eq!(
        list_error(&mut serve_with(legacy, plain).await).await,
        "http_status"
    );
}
