//! The HTTP client: redirect policy, timeouts and error mapping against local
//! fixture servers.

use std::time::Duration;

use axum::Router;
use axum::extract::Path;
use axum::response::Redirect;
use axum::routing::{get, post};
use mcpjump::error::{Error, ErrorKind};
use mcpjump::http::client::{HttpClient, Redirects};
use reqwest::Method;
use url::Url;

use crate::support::http::{
    USER_AGENT, after, client, closed_port, far, hang_up, raw, serve, stall,
};

async fn hop(Path(left): Path<u32>) -> axum::response::Response {
    use axum::response::IntoResponse;
    if left == 0 {
        "done".into_response()
    } else {
        Redirect::temporary(&format!("/hop/{}", left - 1)).into_response()
    }
}

async fn hops_server() -> Url {
    serve(Router::new().route("/hop/{left}", get(hop))).await
}

async fn get_path(base: &Url, path: &str) -> Result<reqwest::Response, Error> {
    let http = client();
    let request = http.request(Method::GET, base.join(path).unwrap(), Redirects::SameOrigin);
    http.send(request, far()).await
}

fn origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

#[tokio::test]
async fn follows_up_to_five_same_origin_redirects() {
    let base = hops_server().await;
    let response = get_path(&base, "/hop/5").await.unwrap();
    assert_eq!(response.url().path(), "/hop/0");
    assert_eq!(response.text().await.unwrap(), "done");
    let error = get_path(&base, "/hop/6").await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RedirectRejected);
    assert_eq!(
        error.message(),
        format!(
            "{} redirected more than 5 times or to another origin",
            origin(&base)
        )
    );
}

#[tokio::test]
async fn rejects_a_redirect_to_another_origin() {
    let other = hops_server().await;
    let target = other.join("/hop/0").unwrap().to_string();
    let base = serve(Router::new().route(
        "/away",
        get(move || async move { Redirect::temporary(&target) }),
    ))
    .await;
    let error = get_path(&base, "/away").await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RedirectRejected);
}

#[tokio::test]
async fn a_token_post_never_follows_a_redirect() {
    let base = serve(Router::new().route(
        "/token",
        post(|| async { Redirect::temporary("/elsewhere") }),
    ))
    .await;
    let http = client();
    let request = http
        .request(Method::POST, base.join("/token").unwrap(), Redirects::Never)
        .body("grant_type=authorization_code");
    let error = http.send(request, far()).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RedirectRejected);
    assert_eq!(
        error.message(),
        format!(
            "{} answered 307 Temporary Redirect, a redirect this request does not follow",
            origin(&base)
        )
    );
}

#[tokio::test]
async fn a_silent_server_hits_the_request_deadline() {
    let base = raw(stall).await;
    let http = client();
    let request = http.request(Method::GET, base.clone(), Redirects::SameOrigin);
    let error = http.send(request, after(200)).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestTimeout);
    assert_eq!(
        error.message(),
        format!("{} did not answer before the deadline", origin(&base))
    );
}

#[tokio::test]
async fn a_stalled_handshake_hits_the_connect_timeout() {
    let mut base = raw(stall).await;
    base.set_scheme("https").unwrap();
    let http = client();
    let request = http.request(Method::GET, base.clone(), Redirects::SameOrigin);
    let error = http.send(request, far()).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConnectTimeout);
    assert_eq!(
        error.message(),
        format!("could not connect to {} within 300ms", origin(&base))
    );
}

#[tokio::test]
async fn refused_and_dropped_connections_are_network_errors() {
    for base in [closed_port().await, raw(hang_up).await] {
        let error = get_path(&base, "/").await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Network, "{base}");
        let prefix = format!("could not reach {}: ", origin(&base));
        assert!(error.message().starts_with(&prefix), "{}", error.message());
        assert!(!error.message().ends_with(": "), "{}", error.message());
    }
}

#[tokio::test]
async fn an_unbuildable_request_is_an_invalid_header() {
    let base = hops_server().await;
    let http = client();
    let request = http
        .request(Method::GET, base, Redirects::SameOrigin)
        .header("bad name", "x");
    let error = http.send(request, far()).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidHeader);
    assert!(
        error.message().starts_with("could not build the request: "),
        "{}",
        error.message()
    );
}

#[test]
fn a_bad_user_agent_fails_client_setup() {
    let error = HttpClient::new(Duration::from_secs(1), "bad\nagent").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Network);
    assert!(
        error
            .message()
            .starts_with("could not set up the HTTP client: "),
        "{}",
        error.message()
    );
    assert!(HttpClient::new(Duration::from_secs(1), USER_AGENT).is_ok());
}
