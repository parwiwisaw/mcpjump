//! Bounded SSE: the byte guard on its own, then whole streams against local
//! fixture servers.

use std::collections::VecDeque;
use std::time::Duration;

use axum::Router;
use axum::http::header;
use axum::routing::get;
use bytes::Bytes;
use futures::StreamExt;
use mcpjump::error::{Error, ErrorKind};
use mcpjump::http::client::Redirects;
use mcpjump::http::sse::{MAX_BUFFERED_EVENTS, SseGuard, SseLimits, events};
use reqwest::Method;
use sse_stream::{Error as SseError, Sse};
use tokio::time::Instant;
use url::Url;

use crate::support::http::{after, client, drip, far, raw, serve, short_sse};

/// Feeds `chunks` in order; returns the parts and whether each chunk ended a line.
fn feed_all(guard: &mut SseGuard, chunks: &[&'static str]) -> (Vec<Bytes>, Vec<bool>) {
    let mut out = VecDeque::new();
    let ended = chunks
        .iter()
        .map(|chunk| {
            guard
                .feed(Bytes::from_static(chunk.as_bytes()), &mut out)
                .unwrap()
        })
        .collect();
    (out.into(), ended)
}

#[test]
fn the_guard_passes_bytes_through_and_reports_line_ends() {
    let mut guard = SseGuard::new(16);
    let (parts, ended) = feed_all(&mut guard, &["data: a", "\r", "\ndata: b\r\n\r\n", ""]);
    assert_eq!(parts.concat(), b"data: a\r\ndata: b\r\n\r\n");
    assert_eq!(ended, [false, true, true, false]);
}

#[test]
fn the_guard_counts_one_event_across_lines_and_chunks() {
    let mut guard = SseGuard::new(12);
    feed_all(&mut guard, &["data: a\n", "\n\n", "data: 1\ndata"]);
    let mut out = VecDeque::new();
    let error = guard
        .feed(Bytes::from_static(b": 2"), &mut out)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ResponseTooLarge);
    assert_eq!(error.message(), "an SSE event is larger than 12 bytes");
}

#[test]
fn a_blank_line_resets_the_event_count() {
    let mut guard = SseGuard::new(8);
    let (parts, _) = feed_all(&mut guard, &["data: a\r\rdata: b\n\ndata: c\r\n"]);
    assert_eq!(parts.len(), 1);
}

#[test]
fn chunks_are_cut_after_every_64_events() {
    let mut guard = SseGuard::new(8);
    let chunk = "data: x\n\n".repeat(2 * MAX_BUFFERED_EVENTS + 1);
    let mut out = VecDeque::new();
    assert!(guard.feed(Bytes::from(chunk), &mut out).unwrap());
    let lengths: Vec<usize> = out.iter().map(Bytes::len).collect();
    assert_eq!(lengths, [64 * 9, 64 * 9, 9]);
}

fn limits(max_event_bytes: usize, idle_millis: u64, deadline: Instant) -> SseLimits {
    SseLimits {
        max_event_bytes,
        idle: Duration::from_millis(idle_millis),
        deadline,
    }
}

async fn sse_server(parts: Vec<&'static str>, gap: Duration) -> Url {
    serve(Router::new().route(
        "/",
        get(move || async move {
            (
                [(header::CONTENT_TYPE, "text/event-stream")],
                drip(parts, gap),
            )
        }),
    ))
    .await
}

async fn collect(base: Url, limits: SseLimits) -> Vec<Result<Sse, SseError>> {
    let http = client();
    let request = http.request(Method::GET, base, Redirects::SameOrigin);
    let response = http.send(request, far()).await.unwrap();
    events(response, limits).collect().await
}

fn data(item: &Result<Sse, SseError>) -> &str {
    item.as_ref().unwrap().data.as_deref().unwrap()
}

/// The mcpjump error inside a failed stream item.
fn failure(item: &Result<Sse, SseError>) -> &Error {
    let inner = item.as_ref().err().and_then(|error| match error {
        SseError::Body(inner) => inner.downcast_ref::<Error>(),
        _ => None,
    });
    inner.unwrap()
}

#[tokio::test]
async fn events_arrive_in_order_across_split_chunks() {
    let base = sse_server(
        vec!["data: one\r", "\n\r\ndata: tw", "o\n\n"],
        Duration::ZERO,
    )
    .await;
    let items = collect(base, limits(64, 1000, far())).await;
    let data: Vec<&str> = items.iter().map(data).collect();
    assert_eq!(data, ["one", "two"]);
}

#[tokio::test]
async fn a_chunk_of_many_events_is_parsed_in_parts() {
    let count = 2 * MAX_BUFFERED_EVENTS + 2;
    let chunk: &'static str = "data: x\n\n".repeat(count).leak();
    let base = sse_server(vec![chunk], Duration::ZERO).await;
    let items = collect(base, limits(64, 1000, far())).await;
    assert_eq!(items.len(), count);
    assert!(items.iter().all(|item| data(item) == "x"));
}

#[tokio::test]
async fn an_oversized_event_ends_the_stream() {
    let base = sse_server(vec!["data: ok\n\n", "data: 0123456789\n\n"], Duration::ZERO).await;
    let items = collect(base, limits(10, 1000, far())).await;
    assert_eq!(items.len(), 2);
    assert_eq!(data(&items[0]), "ok");
    assert_eq!(failure(&items[1]).kind(), ErrorKind::ResponseTooLarge);
}

#[tokio::test]
async fn an_error_discards_the_events_queued_before_it() {
    let chunk = "data: x\n\n".repeat(MAX_BUFFERED_EVENTS + 1) + "data: 0123456789\n\n";
    let base = sse_server(vec![chunk.leak()], Duration::ZERO).await;
    let items = collect(base, limits(10, 1000, far())).await;
    assert_eq!(items.len(), 1);
    assert_eq!(failure(&items[0]).kind(), ErrorKind::ResponseTooLarge);
}

#[tokio::test]
async fn a_drip_without_line_ends_hits_the_idle_timeout() {
    let base = sse_server(
        vec!["d", "a", "t", "a", ":", " ", "x"],
        Duration::from_millis(100),
    )
    .await;
    let items = collect(base.clone(), limits(64, 350, far())).await;
    let error = failure(&items[0]);
    assert_eq!(error.kind(), ErrorKind::StreamTimeout);
    assert_eq!(
        error.message(),
        format!(
            "{} sent no complete SSE line for 350ms",
            base.origin().ascii_serialization()
        )
    );
    assert_eq!(items.len(), 1);
}

#[tokio::test]
async fn comment_lines_keep_the_stream_alive_until_the_deadline() {
    let base = sse_server(vec![": ping\n"; 20], Duration::from_millis(100)).await;
    let items = collect(base.clone(), limits(64, 250, after(700))).await;
    let error = failure(&items[0]);
    assert_eq!(error.kind(), ErrorKind::StreamTimeout);
    assert_eq!(
        error.message(),
        format!(
            "the SSE stream from {} did not finish before the deadline",
            base.origin().ascii_serialization()
        )
    );
}

#[tokio::test]
async fn a_broken_transfer_ends_the_stream_with_a_network_error() {
    let base = raw(short_sse).await;
    let items = collect(base, limits(64, 1000, far())).await;
    assert_eq!(items.len(), 2);
    assert_eq!(data(&items[0]), "a");
    assert_eq!(failure(&items[1]).kind(), ErrorKind::Network);
}
