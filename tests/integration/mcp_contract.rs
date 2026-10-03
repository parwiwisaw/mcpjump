//! The `McpSession` contract: the same list, call and close on the real
//! connector against a scripted server of each protocol generation, and on
//! the `FakeSession` the command tests use.

use std::sync::Arc;

use mcpjump::config::model::{Generation, Transport};
use mcpjump::error::ErrorKind;
use mcpjump::mcp::connector::Target;
use mcpjump::mcp::session::{McpSession, ToolResult};
use serde_json::json;

use crate::support::fakes::connector::{FakeSession, tool};
use crate::support::mcp_client::{arguments, connect, target};
use crate::support::mcp_server::{
    ENDPOINT, SESSION, entries, legacy, modern, sse, sse_answer, streamable,
};

/// Lists, calls `echo` and closes.
async fn exercise(mut session: Box<dyn McpSession>) {
    let page = session.list_tools_page(None).await.unwrap();
    assert_eq!(page.tools[0].name, "echo");
    assert_eq!(page.next_cursor, None);
    let result = session.call_tool("echo", arguments()).await.unwrap();
    assert!(!result.is_error);
    assert_eq!(result.value["content"][0]["text"], r#"{"n":1}"#);
    session.close().await;
}

/// Connects and exercises the session; returns the generation that
/// answered.
async fn round_trip(target: Target) -> Generation {
    let connection = connect(target).await.unwrap();
    exercise(connection.session).await;
    connection.generation
}

#[tokio::test]
async fn a_modern_server_answers_without_a_session() {
    let (url, log) = streamable(Arc::new(modern)).await;
    let generation = round_trip(target(url, Transport::Http, None)).await;
    assert_eq!(generation, Generation::Modern);
    assert_eq!(
        entries(&log),
        ["server/discover", "tools/list", "tools/call"]
    );
}

#[tokio::test]
async fn a_legacy_streamable_server_is_found_after_modern() {
    let (url, log) = streamable(Arc::new(legacy)).await;
    let generation = round_trip(target(url, Transport::Http, None)).await;
    assert_eq!(generation, Generation::LegacyStreamable);
    let session = |method: &str| format!("{method}@{SESSION}");
    assert_eq!(
        entries(&log),
        [
            "server/discover".to_owned(),
            "initialize".to_owned(),
            session("notifications/initialized"),
            session("tools/list"),
            session("tools/call"),
            session("delete"),
        ]
    );
}

#[tokio::test]
async fn an_sse_server_is_found_last() {
    let (url, log) = sse(ENDPOINT, Arc::new(sse_answer)).await;
    let generation = round_trip(target(url, Transport::Http, None)).await;
    assert_eq!(generation, Generation::Sse);
    assert_eq!(
        entries(&log),
        [
            "initialize",
            "notifications/initialized",
            "tools/list",
            "tools/call"
        ]
    );
}

#[tokio::test]
async fn no_generation_answering_is_unsupported_server() {
    let (url, _log) = sse("event: other\ndata: x\n\n", Arc::new(sse_answer)).await;
    let error = connect(target(url.join("nothing").unwrap(), Transport::Http, None))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnsupportedServer);
}

#[tokio::test]
async fn the_fake_session_keeps_the_same_contract() {
    let result = ToolResult {
        value: json!({"content": [{"type": "text", "text": r#"{"n":1}"#}]}),
        is_error: false,
    };
    let fake = FakeSession::default()
        .page(&[tool("echo", &json!({"type": "object"}))], None)
        .call(Ok(result));
    let log = fake.log();
    exercise(Box::new(fake)).await;
    assert_eq!(entries(&log), ["list ", r#"call echo {"n":1}"#, "close"]);
}

#[tokio::test]
async fn a_legacy_session_is_deleted_with_the_configured_headers() {
    let (url, log) = streamable(Arc::new(legacy)).await;
    let mut keyed = target(url, Transport::Http, None);
    keyed.headers = vec![("X-Key".to_owned(), "k1".to_owned())];
    round_trip(keyed).await;
    let deleted = format!("delete@{SESSION} x-key=k1");
    assert_eq!(entries(&log).last(), Some(&deleted));
}
