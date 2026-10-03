//! HTTP+SSE streams and posts the connector refuses.

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use mcpjump::config::model::Transport;
use mcpjump::mcp::connector::Target;
use url::Url;

use crate::support::http::{closed_port, serve};
use crate::support::mcp_client::{connect, connect_error, target};
use crate::support::mcp_server::{
    ENDPOINT, Received, answer, entries, frame, modern, sse, sse_answer, streamable,
};

fn forced(url: Url) -> Target {
    target(url, Transport::Sse, None)
}

/// A target whose requests time out after one second.
fn impatient(url: Url) -> Target {
    let mut target = forced(url);
    target.limits.request_timeout_secs = 1;
    target
}

async fn stream_answering(get_answer: fn() -> axum::response::Response) -> Url {
    let router = Router::new().route("/sse", get(move || async move { get_answer() }));
    serve(router).await.join("sse").unwrap()
}

#[tokio::test]
async fn forcing_sse_skips_streamable_http() {
    let (url, log) = streamable(Arc::new(modern)).await;
    assert_eq!(connect_error(forced(url)).await, "unsupported_server");
    assert_eq!(entries(&log), Vec::<String>::new());
}

#[tokio::test]
async fn the_stream_must_open_authorized_as_an_event_stream() {
    let denied = stream_answering(|| StatusCode::UNAUTHORIZED.into_response()).await;
    assert_eq!(connect_error(forced(denied)).await, "auth_required");
    let text = stream_answering(|| "hello".into_response()).await;
    assert_eq!(connect_error(forced(text)).await, "unsupported_server");
    let closed = closed_port().await.join("sse").unwrap();
    assert_eq!(connect_error(forced(closed)).await, "network");
}

#[tokio::test]
async fn the_endpoint_event_must_come_first_and_in_time() {
    let (other, _log) = sse("event: other\ndata: x\n\n", Arc::new(sse_answer)).await;
    assert_eq!(connect_error(forced(other)).await, "protocol_error");
    let (silent, _log) = sse("", Arc::new(sse_answer)).await;
    assert_eq!(connect_error(impatient(silent)).await, "request_timeout");
}

#[tokio::test]
async fn a_refused_post_names_its_status() {
    let (denied, _log) = sse(
        ENDPOINT,
        Arc::new(|_: &Received| (StatusCode::FORBIDDEN, Vec::new())),
    )
    .await;
    assert_eq!(connect_error(forced(denied)).await, "auth_required");
    let (failing, _log) = sse(
        ENDPOINT,
        Arc::new(|_: &Received| (StatusCode::BAD_GATEWAY, Vec::new())),
    )
    .await;
    assert_eq!(connect_error(forced(failing)).await, "http_status");
}

#[tokio::test]
async fn a_handshake_with_no_answer_times_out() {
    let (url, _log) = sse(
        ENDPOINT,
        Arc::new(|_: &Received| (StatusCode::ACCEPTED, Vec::new())),
    )
    .await;
    assert_eq!(connect_error(impatient(url)).await, "request_timeout");
}

#[tokio::test]
async fn other_events_are_skipped_and_a_broken_message_ends_the_session() {
    let (url, _log) = sse(
        ENDPOINT,
        Arc::new(|received: &Received| {
            let frames = match received.method.as_str() {
                "tools/list" => vec!["data: {\n\n".to_owned()],
                _ => std::iter::once("event: other\ndata: x\n\n".to_owned())
                    .chain(answer(received).iter().map(frame))
                    .collect(),
            };
            (StatusCode::ACCEPTED, frames)
        }),
    )
    .await;
    let mut connection = connect(forced(url)).await.unwrap();
    let error = connection.session.list_tools_page(None).await.unwrap_err();
    assert_eq!(error.kind().as_str(), "protocol_error");
    connection.session.close().await;
}
