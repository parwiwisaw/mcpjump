//! How the probe reads a Streamable HTTP server's first answers: which
//! move on to the next generation and which end the probe.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures::stream;
use mcpjump::config::model::Generation;
use rmcp::model::{ErrorCode, ErrorData, ServerJsonRpcMessage};
use serde_json::json;

use crate::support::mcp_client::{connect, connect_error, http};
use crate::support::mcp_server::{
    Log, Received, entries, json, legacy, modern, rpc_error, streamable,
};

/// A `-32022` answer naming the versions the server speaks.
fn unsupported_version(received: &Received, supported: &str) -> Response {
    let data = ErrorData::new(
        ErrorCode::UNSUPPORTED_PROTOCOL_VERSION,
        "server secret",
        Some(json!({ "supported": [supported] })),
    );
    json(&ServerJsonRpcMessage::error(data, received.id.clone()))
}

/// Serves `discover` for `server/discover` and a Legacy Streamable server
/// otherwise; returns the generation found and the log.
async fn found_after(
    discover: impl Fn(&Received) -> Response + Send + Sync + 'static,
) -> (Generation, Log) {
    let (url, log) = streamable(Arc::new(move |received: &Received| {
        if received.method == "server/discover" {
            discover(received)
        } else {
            legacy(received)
        }
    }))
    .await;
    let connection = connect(http(url)).await.unwrap();
    (connection.generation, log)
}

#[tokio::test]
async fn an_unsupported_version_is_retried_once_on_a_version_both_speak() {
    let rejected = AtomicUsize::new(0);
    let (generation, log) = found_after(move |received| {
        if rejected.fetch_add(1, Ordering::SeqCst) == 0 {
            unsupported_version(received, "2026-07-28")
        } else {
            modern(received)
        }
    })
    .await;
    assert_eq!(generation, Generation::Modern);
    assert_eq!(entries(&log), ["server/discover", "server/discover"]);
}

#[tokio::test]
async fn no_shared_version_moves_on_to_legacy() {
    let (generation, _log) =
        found_after(|received| unsupported_version(received, "1999-01-01")).await;
    assert_eq!(generation, Generation::LegacyStreamable);
}

#[tokio::test]
async fn discover_rejected_with_400_404_or_405_is_a_legacy_server() {
    let statuses = [
        StatusCode::BAD_REQUEST,
        StatusCode::NOT_FOUND,
        StatusCode::METHOD_NOT_ALLOWED,
    ];
    for status in statuses {
        for with_body in [false, true] {
            let (generation, log) = found_after(move |received| {
                if with_body {
                    (
                        status,
                        json(&rpc_error(received, ErrorCode::METHOD_NOT_FOUND)),
                    )
                        .into_response()
                } else {
                    status.into_response()
                }
            })
            .await;
            assert_eq!(generation, Generation::LegacyStreamable);
            assert_eq!(entries(&log)[1], "initialize");
        }
    }
}

#[tokio::test]
async fn a_modern_rejection_ends_the_probe() {
    let (url, log) = streamable(Arc::new(|received: &Received| {
        let error = rpc_error(received, ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY);
        (StatusCode::BAD_REQUEST, json(&error)).into_response()
    }))
    .await;
    assert_eq!(connect_error(http(url)).await, "server_error");
    assert_eq!(entries(&log), ["server/discover"]);
}

#[tokio::test]
async fn a_timeout_ends_the_probe_without_a_downgrade() {
    let (url, log) = streamable(Arc::new(|_: &Received| {
        let silent = stream::pending::<Result<Vec<u8>, std::io::Error>>();
        (
            [("content-type", "application/json")],
            Body::from_stream(silent),
        )
            .into_response()
    }))
    .await;
    let mut quick = http(url);
    quick.limits.request_timeout_secs = 1;
    assert_eq!(connect_error(quick).await, "request_timeout");
    assert_eq!(entries(&log), ["server/discover"]);
}

#[tokio::test]
async fn a_legacy_server_may_keep_no_session() {
    let (url, log) = streamable(Arc::new(|received: &Received| {
        match received.method.as_str() {
            "server/discover" => StatusCode::BAD_REQUEST.into_response(),
            _ => modern(received),
        }
    }))
    .await;
    let mut connection = connect(http(url)).await.unwrap();
    assert_eq!(connection.generation, Generation::LegacyStreamable);
    connection.session.list_tools_page(None).await.unwrap();
    connection.session.close().await;
    assert_eq!(
        entries(&log),
        [
            "server/discover",
            "initialize",
            "notifications/initialized",
            "tools/list"
        ]
    );
}
