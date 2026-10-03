//! The rules for URLs a server advertises.

use mcpjump::error::ErrorKind;
use mcpjump::http::url_policy::{HostCategory, UrlPolicy, host_category};
use url::Url;

fn url(raw: &str) -> Url {
    Url::parse(raw).unwrap()
}

#[test]
fn hosts_are_classified_by_literal_address() {
    let cases = [
        ("https://example.com/", HostCategory::Public),
        ("https://8.8.8.8/", HostCategory::Public),
        ("https://[2001:db8::1]/", HostCategory::Public),
        ("http://localhost/", HostCategory::Loopback),
        ("http://api.localhost/", HostCategory::Loopback),
        ("http://127.0.0.2/", HostCategory::Loopback),
        ("http://0.0.0.0/", HostCategory::Loopback),
        ("http://[::1]/", HostCategory::Loopback),
        ("http://[::]/", HostCategory::Loopback),
        ("http://[::ffff:127.0.0.1]/", HostCategory::Loopback),
        ("https://10.1.2.3/", HostCategory::Private),
        ("https://192.168.0.1/", HostCategory::Private),
        ("https://[fd00::1]/", HostCategory::Private),
        ("https://[::ffff:10.0.0.1]/", HostCategory::Private),
        ("http://169.254.169.254/", HostCategory::LinkLocal),
        ("https://[fe80::1]/", HostCategory::LinkLocal),
        ("data:text/plain,x", HostCategory::Public),
    ];
    for (raw, category) in cases {
        assert_eq!(host_category(&url(raw)), category, "{raw}");
    }
}

fn rejection(server: &str, advertised: &str) -> Option<String> {
    UrlPolicy::new(url(server))
        .check("token endpoint", &url(advertised))
        .err()
        .map(|error| {
            assert_eq!(error.kind(), ErrorKind::UrlRejected);
            error.message().to_owned()
        })
}

const PUBLIC: &str = "https://mcp.example.com/mcp";
const LOOPBACK_HTTP: &str = "http://127.0.0.1:8080/mcp";

#[test]
fn allowed_urls_pass() {
    let cases = [
        (PUBLIC, "https://auth.example.org/token"),
        (PUBLIC, "https://8.8.8.8/token"),
        (LOOPBACK_HTTP, "http://localhost:9000/token"),
        (LOOPBACK_HTTP, "https://[::1]/token"),
        ("https://10.0.0.5/mcp", "https://10.9.9.9/token"),
    ];
    for (server, advertised) in cases {
        assert_eq!(rejection(server, advertised), None, "{server} {advertised}");
    }
}

#[test]
fn each_rule_names_itself() {
    let http_rule = "token endpoint URL rejected: use https; http is allowed only on loopback, for a server configured on loopback http";
    let address_rule = "token endpoint URL rejected: it is a loopback, private or link-local address, and the configured server is not";
    let cases = [
        (PUBLIC, "http://auth.example.org/token", http_rule),
        ("https://localhost/mcp", "http://localhost/token", http_rule),
        (LOOPBACK_HTTP, "http://example.org/token", http_rule),
        (
            PUBLIC,
            "ftp://auth.example.org/",
            "token endpoint URL rejected: use https",
        ),
        (
            PUBLIC,
            "https://user@auth.example.org/",
            "token endpoint URL rejected: credentials in the URL are not allowed",
        ),
        (
            PUBLIC,
            "https://:secret@auth.example.org/",
            "token endpoint URL rejected: credentials in the URL are not allowed",
        ),
        (PUBLIC, "https://169.254.169.254/token", address_rule),
        (PUBLIC, "https://127.0.0.1/token", address_rule),
        (
            "https://10.0.0.5/mcp",
            "https://[fe80::1]/token",
            address_rule,
        ),
    ];
    for (server, advertised, message) in cases {
        assert_eq!(
            rejection(server, advertised).as_deref(),
            Some(message),
            "{server} {advertised}"
        );
    }
}

#[test]
fn long_urls_and_fragments_are_rejected() {
    let base = "https://auth.example.org/";
    let at_limit = format!("{base}{}", "a".repeat(2048 - base.len()));
    let over = format!("{at_limit}a");
    assert_eq!(rejection(PUBLIC, &at_limit), None);
    assert_eq!(
        rejection(PUBLIC, &over).as_deref(),
        Some("token endpoint URL rejected: it is longer than 2048 bytes")
    );
    assert_eq!(
        rejection(PUBLIC, "https://auth.example.org/token#x").as_deref(),
        Some("token endpoint URL rejected: a fragment (#...) is not allowed")
    );
}

#[test]
fn http_needs_a_loopback_name_or_address_not_just_the_category() {
    let http_rule = "token endpoint URL rejected: use https; http is allowed only on loopback, for a server configured on loopback http";
    for advertised in [
        "http://0.0.0.0/token",
        "http://[::]/token",
        "http://api.localhost/token",
    ] {
        assert_eq!(
            rejection(LOOPBACK_HTTP, advertised).as_deref(),
            Some(http_rule),
            "{advertised}"
        );
        let https = advertised.replacen("http", "https", 1);
        assert_eq!(rejection(LOOPBACK_HTTP, &https), None, "{https}");
    }
}

#[test]
fn the_sse_endpoint_must_share_the_server_origin() {
    let policy = UrlPolicy::new(url(PUBLIC));
    assert_eq!(
        policy.check_endpoint(&url("https://mcp.example.com/messages?s=1")),
        Ok(())
    );
    let cases = [
        (
            "https://other.example.com/messages",
            "SSE endpoint URL rejected: it must be on the server's origin",
        ),
        (
            "http://mcp.example.com/messages",
            "SSE endpoint URL rejected: use https; http is allowed only on loopback, for a server configured on loopback http",
        ),
    ];
    for (endpoint, message) in cases {
        let error = policy.check_endpoint(&url(endpoint)).unwrap_err();
        assert_eq!(error.message(), message, "{endpoint}");
    }
}

#[test]
fn credentials_go_only_to_the_server_origin() {
    let policy = UrlPolicy::new(url(PUBLIC));
    assert!(policy.may_send_credentials(&url("https://mcp.example.com/other")));
    assert!(!policy.may_send_credentials(&url("https://mcp.example.com:8443/mcp")));
    assert!(!policy.may_send_credentials(&url("https://auth.example.com/mcp")));
}
