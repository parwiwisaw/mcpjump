//! Local fixture servers for the HTTP tests: axum routers for well-formed
//! HTTP, and raw TCP handlers for peers that stall or hang up.

use std::convert::Infallible;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use futures::StreamExt as _;
use futures::stream;
use mcpjump::http::client::HttpClient;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use url::Url;

/// The user agent the tests send.
pub(crate) const USER_AGENT: &str = "mcpjump-test";

/// A client with a short connect timeout.
pub(crate) fn client() -> HttpClient {
    HttpClient::new(Duration::from_millis(300), USER_AGENT).unwrap()
}

/// A deadline `millis` from now.
pub(crate) fn after(millis: u64) -> Instant {
    Instant::now() + Duration::from_millis(millis)
}

/// A deadline no test reaches.
pub(crate) fn far() -> Instant {
    after(30_000)
}

async fn listen() -> (TcpListener, Url) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    (listener, url)
}

/// Serves `router` on a fresh loopback port and returns its base URL.
pub(crate) async fn serve(router: Router) -> Url {
    let (listener, url) = listen().await;
    tokio::spawn(async move { axum::serve(listener, router).await });
    url
}

/// Accepts connections and hands each to `handle`, which may stall or hang
/// up. The stream is dropped when `handle` returns.
pub(crate) async fn raw(handle: fn(TcpStream) -> RawFuture) -> Url {
    let (listener, url) = listen().await;
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(handle(socket));
        }
    });
    url
}

/// What a raw handler returns.
pub(crate) type RawFuture = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

/// Holds the connection open without answering.
pub(crate) fn stall(socket: TcpStream) -> RawFuture {
    Box::pin(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(socket);
    })
}

/// Hangs up at once.
pub(crate) fn hang_up(socket: TcpStream) -> RawFuture {
    Box::pin(async move { drop(socket) })
}

/// Promises 100 bytes, sends 5, then hangs up.
pub(crate) fn short_body(mut socket: TcpStream) -> RawFuture {
    Box::pin(async move {
        let head = "HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nhello";
        socket.write_all(head.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    })
}

/// Starts an SSE response promising 1000 bytes, sends one event, then hangs
/// up.
pub(crate) fn short_sse(mut socket: TcpStream) -> RawFuture {
    Box::pin(async move {
        let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: 1000\r\n\r\ndata: a\n\n";
        socket.write_all(head.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    })
}

/// A port nothing listens on.
pub(crate) async fn closed_port() -> Url {
    let (listener, url) = listen().await;
    drop(listener);
    url
}

/// A body that sends `parts` with `gap` before each, then ends.
pub(crate) fn drip(parts: Vec<&'static str>, gap: Duration) -> Body {
    let parts = stream::iter(parts).then(move |part| async move {
        tokio::time::sleep(gap).await;
        Ok::<_, Infallible>(Bytes::from_static(part.as_bytes()))
    });
    Body::from_stream(parts)
}
