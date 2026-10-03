//! Phase 6b regression contracts for the in-house MCP client.

use mcpjump::config::model::Generation;
use serde_json::{Value, json};

use crate::mcp_wire::{
    called, discover, error, exercise, frame, http_sse, labels, legacy, listing, modern, quick,
    reply, session_headers, status,
};
use crate::support::mcp_client::connect;
use crate::support::raw_mcp_server::{Fixture, Step};

/// An SSE method-not-found error must fall back to Legacy Streamable.
#[tokio::test]
async fn cepo_exact_sse_error_falls_back_and_echoes_session() {
    let mut steps = vec![reply(
        "server/discover",
        error(0, -32601, &Value::Null),
        true,
    )];
    steps.extend(legacy("2025-03-26", true, true));
    steps.extend([
        reply("tools/list", listing(1), true),
        reply("tools/call", called(2), true),
        status("DELETE", 200),
    ]);
    let fixture = Fixture::new(steps).await;
    let outcome = connect(quick(&fixture, None)).await;
    assert!(outcome.is_ok(), "{outcome:?}; wire: {:?}", labels(&fixture));
    let connection = outcome.unwrap();
    assert_eq!(connection.generation, Generation::LegacyStreamable);
    exercise(connection).await;
    session_headers(&fixture, 2);
    fixture.finished();
}

/// Header mismatch is a correlated Modern rejection, even in an SSE event.
#[tokio::test]
async fn modern_sse_header_mismatch_is_server_error() {
    sse_rejection(-32020).await;
}

/// Missing client capabilities are a Modern rejection, even in an SSE event.
#[tokio::test]
async fn modern_sse_missing_capability_is_server_error() {
    sse_rejection(-32021).await;
}

/// Checks classification, correlation, code and no fallback for one rejection.
async fn sse_rejection(code: i32) {
    let fixture = Fixture::new(vec![reply(
        "server/discover",
        error(0, code, &Value::Null),
        true,
    )])
    .await;
    let failed = connect(quick(&fixture, None)).await.unwrap_err();
    assert_eq!(
        failed.kind().as_str(),
        "server_error",
        "{}",
        failed.message()
    );
    assert!(
        failed
            .message()
            .ends_with(&format!("JSON-RPC error {code}"))
    );
    assert!(!failed.message().contains("secret"));
    fixture.finished();
}

/// An SSE unsupported-version error permits one retry, then Legacy fallback.
#[tokio::test]
async fn modern_sse_version_retry_exhausts_before_legacy() {
    let mut steps = vec![
        reply(
            "server/discover",
            error(0, -32022, &json!({"supported":["2026-07-28"]})),
            true,
        ),
        reply(
            "server/discover",
            error(1, -32022, &json!({"supported":["2026-07-28"]})),
            true,
        ),
    ];
    steps.extend(legacy("2025-11-25", false, false));
    let fixture = Fixture::new(steps).await;
    let outcome = connect(quick(&fixture, None)).await;
    assert!(outcome.is_ok(), "{outcome:?}; wire: {:?}", labels(&fixture));
    let connection = outcome.unwrap();
    assert_eq!(connection.generation, Generation::LegacyStreamable);
    connection.session.close().await;
    fixture.finished();
}

/// Modern server requests fail the operation and must generate no response POST.
#[tokio::test]
async fn modern_server_request_is_protocol_error_without_reply_post() {
    let mut steps = modern(false);
    let bytes = format!(
        "{}{}",
        frame(r#"{"jsonrpc":"2.0","id":90,"method":"ping"}"#),
        frame(&listing(1))
    );
    steps.push(Step::new("tools/list", 200, "text/event-stream", bytes));
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, None)).await.unwrap();
    let failed = connection.session.list_tools_page(None).await.unwrap_err();
    assert_eq!(failed.kind().as_str(), "protocol_error");
    connection.session.close().await;
    assert_eq!(labels(&fixture), ["server/discover", "tools/list"]);
    fixture.finished();
}

/// Unsupported Legacy versions must reject that generation before initialized is sent.
#[tokio::test]
async fn unsupported_legacy_version_is_rejected_as_json_and_sse() {
    for sse in [false, true] {
        let init = legacy("1999-01-01", sse, false).remove(0);
        let fixture = Fixture::new(vec![init, reply("server/discover", discover(0), false)]).await;
        let outcome = connect(quick(&fixture, Some(Generation::LegacyStreamable))).await;
        assert!(outcome.is_ok(), "{outcome:?}; wire: {:?}", labels(&fixture));
        let connection = outcome.unwrap();
        assert_eq!(
            connection.generation,
            Generation::Modern,
            "wire: {:?}",
            labels(&fixture)
        );
        connection.session.close().await;
        fixture.finished();
    }
}

/// A forced HTTP+SSE client must offer 2024-11-05, not a Streamable version.
#[tokio::test]
async fn http_sse_initialize_offers_2024_11_05() {
    let fixture = Fixture::new(http_sse()).await;
    let connection = connect(quick(&fixture, Some(Generation::Sse)))
        .await
        .unwrap();
    connection.session.close().await;
    fixture.finished();
    assert_eq!(
        fixture.received()[1].body["params"]["protocolVersion"],
        "2024-11-05"
    );
}
