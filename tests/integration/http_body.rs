//! Size-bounded body reads against local fixture servers.

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use mcpjump::error::{Error, ErrorKind};
use mcpjump::http::body::{SizeLimit, read_body};
use mcpjump::http::client::Redirects;
use reqwest::Method;
use tokio::time::Instant;
use url::Url;

use crate::support::http::{after, client, drip, far, raw, serve, short_body};

/// `/fixed` has a `Content-Length`; `/chunked` streams without one.
async fn bodies() -> Url {
    serve(
        Router::new()
            .route("/fixed", get(|| async { "0123456789" }))
            .route(
                "/chunked",
                get(|| async { drip(vec!["01234", "56789"], Duration::ZERO) }),
            )
            .route(
                "/slow",
                get(|| async { drip(vec!["a", "b", "c", "d"], Duration::from_millis(150)) }),
            ),
    )
    .await
}

async fn read(url: Url, limit: SizeLimit, deadline: Instant) -> Result<Vec<u8>, Error> {
    let http = client();
    let request = http.request(Method::GET, url, Redirects::SameOrigin);
    let response = http.send(request, far()).await.unwrap();
    read_body(response, limit, deadline).await
}

fn origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

#[tokio::test]
async fn a_body_at_the_limit_is_read_whole() {
    let base = bodies().await;
    for path in ["/fixed", "/chunked"] {
        let body = read(base.join(path).unwrap(), SizeLimit::response(10), far())
            .await
            .unwrap();
        assert_eq!(body, b"0123456789", "{path}");
    }
}

#[tokio::test]
async fn a_body_over_the_limit_fails_with_the_limit_kind() {
    let base = bodies().await;
    let cases = [
        (
            "/fixed",
            SizeLimit::metadata(9),
            ErrorKind::MetadataTooLarge,
        ),
        (
            "/chunked",
            SizeLimit::response(9),
            ErrorKind::ResponseTooLarge,
        ),
    ];
    for (path, limit, kind) in cases {
        let error = read(base.join(path).unwrap(), limit, far())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), kind, "{path}");
        assert_eq!(
            error.message(),
            format!("the response from {} is larger than 9 bytes", origin(&base))
        );
    }
}

#[tokio::test]
async fn a_slow_drip_hits_the_deadline() {
    let base = bodies().await;
    let error = read(
        base.join("/slow").unwrap(),
        SizeLimit::response(10),
        after(300),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestTimeout);
}

#[tokio::test]
async fn a_body_cut_short_is_a_network_error() {
    let base = raw(short_body).await;
    let error = read(base.clone(), SizeLimit::response(1000), far())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Network);
    let prefix = format!("could not reach {}: ", origin(&base));
    assert!(error.message().starts_with(&prefix), "{}", error.message());
}

#[tokio::test]
async fn an_empty_body_is_empty() {
    let base = serve(Router::new().route("/", get(|| async { Body::empty() }))).await;
    let body = read(base, SizeLimit::response(1024), far()).await.unwrap();
    assert!(body.is_empty());
}
