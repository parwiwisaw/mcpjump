//! Discovery during `login`, against the OAuth fixture: the challenge's
//! hint, resource metadata, authorization server metadata, the legacy
//! profile, and the token response checks.

use mcpjump::error::Error;
use serde_json::{Value, json};
use url::Url;

use crate::support::Harness;
use crate::support::auth::{failure, harness, refusal, reply, run_watched, unauthorized};
use crate::support::fakes::browser::Behavior;
use crate::support::fakes::connector::FakeConnector;
use crate::support::fakes::user::Act;
use crate::support::oauth_server::{Doc, OAuthServer, Script};

/// A harness whose probe fails with `refused` and whose browser follows
/// the login.
fn probed(server: &OAuthServer, refused: Error, extra: &str) -> Harness {
    let mut h = harness(server, extra);
    h.connector = FakeConnector::answer(Err(refused));
    h.browser.set(Behavior::Follow);
    h
}

/// The error kind and message of a login against a server following
/// `script`, probed with a plain 401.
fn login_fails(script: Script) -> (String, String) {
    let server = OAuthServer::start(script);
    let h = probed(&server, unauthorized(&server), "");
    failure(&run_watched(&h, &["login", "demo"], Act::Wait))
}

fn resource(patch: fn(&mut Value)) -> Script {
    Script {
        resource_doc: Doc::Patched(patch),
        ..Script::default()
    }
}

/// A change to a fixture document.
type Patch = fn(&mut Value);

fn metadata(patch: Patch) -> Script {
    Script {
        metadata_doc: Doc::Patched(patch),
        ..Script::default()
    }
}

/// A server with no resource metadata, so the legacy profile applies.
fn legacy(metadata_doc: Doc) -> Script {
    Script {
        resource_doc: Doc::Status(404),
        metadata_doc,
        ..Script::default()
    }
}

#[test]
fn a_hint_the_url_policy_refuses_is_not_fetched() {
    let server = OAuthServer::start(Script::default());
    let hint = Url::parse("http://example.com/prm").unwrap();
    let h = probed(&server, refusal(401, None, None, Some(hint)), "");
    let (kind, _) = failure(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert_eq!(kind, "url_rejected");
    assert!(server.paths().is_empty());
}

#[test]
fn a_hint_nothing_answers_is_a_network_error() {
    let server = OAuthServer::start(Script::default());
    let hint = Url::parse("http://127.0.0.1:1/prm").unwrap();
    let h = probed(&server, refusal(401, None, None, Some(hint)), "");
    let (kind, _) = failure(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert_eq!(kind, "network");
}

#[test]
fn a_resource_document_over_the_limit_is_refused() {
    let server = OAuthServer::start(resource(|d| d["pad"] = json!("x".repeat(2048))));
    let h = probed(
        &server,
        unauthorized(&server),
        "[limits]\nmax_metadata_bytes = 1024\n",
    );
    let (kind, _) = failure(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert_eq!(kind, "metadata_too_large");
}

#[test]
fn resource_metadata_that_is_not_a_document_fails() {
    let (kind, _) = login_fails(Script {
        resource_doc: Doc::Status(500),
        ..Script::default()
    });
    assert_eq!(kind, "http_status");
    let (kind, message) = login_fails(resource(|d| *d = json!("x")));
    assert_eq!(kind, "protocol_error");
    assert!(message.contains("invalid resource metadata"), "{message}");
}

#[test]
fn resource_metadata_naming_another_resource_fails() {
    let (kind, message) = login_fails(resource(|d| d["resource"] = json!("not a url")));
    assert_eq!(
        (kind.as_str(), message.as_str()),
        ("protocol_error", "the resource is not a valid URL")
    );
    let (kind, _) = login_fails(resource(|d| {
        d["resource"] = json!("http://127.0.0.1:1/mcp");
    }));
    assert_eq!(kind, "resource_mismatch");
}

#[test]
fn resource_metadata_without_a_usable_server_fails() {
    let unusable = "the resource metadata lists no usable authorization server";
    for patch in [
        (|d: &mut Value| d["authorization_servers"] = json!([])) as fn(&mut Value),
        |d| d["authorization_servers"] = json!(vec!["http://127.0.0.1:1"; 65]),
    ] {
        assert_eq!(
            login_fails(resource(patch)),
            ("protocol_error".to_owned(), unusable.to_owned())
        );
    }
    let (kind, _) = login_fails(resource(|d| d["authorization_servers"] = json!(["nope"])));
    assert_eq!(kind, "protocol_error");
    let (kind, _) = login_fails(resource(|d| {
        d["authorization_servers"] = json!(["http://example.com"]);
    }));
    assert_eq!(kind, "url_rejected");
    let malformed = "the resource metadata lists malformed scopes";
    for patch in [
        (|d: &mut Value| d["scopes_supported"] = json!(["a b"])) as Patch,
        |d| d["scopes_supported"] = json!(vec!["s"; 65]),
    ] {
        assert_eq!(
            login_fails(resource(patch)),
            ("protocol_error".to_owned(), malformed.to_owned())
        );
    }
}

#[test]
fn a_server_without_metadata_fails() {
    let (kind, message) = login_fails(Script {
        metadata_doc: Doc::Status(404),
        ..Script::default()
    });
    assert_eq!(kind, "http_status");
    assert!(
        message.ends_with("has no authorization server metadata"),
        "{message}"
    );
    let (kind, _) = login_fails(Script {
        metadata_doc: Doc::Status(500),
        ..Script::default()
    });
    assert_eq!(kind, "http_status");
}

#[test]
fn server_metadata_that_does_not_check_out_fails() {
    let cases: [(Patch, &str); 6] = [
        (|d| *d = json!("x"), "protocol_error"),
        (|d| d["issuer"] = json!("nope"), "protocol_error"),
        (
            |d| d["issuer"] = json!("http://127.0.0.1:1"),
            "protocol_error",
        ),
        (
            |d| d["code_challenge_methods_supported"] = json!(["plain"]),
            "unsupported_feature",
        ),
        (
            |d| d["registration_endpoint"] = json!("http://user@127.0.0.1/"),
            "url_rejected",
        ),
        (
            |d| d["authorization_endpoint"] = json!("nope"),
            "protocol_error",
        ),
    ];
    for (patch, expected) in cases {
        assert_eq!(login_fails(metadata(patch)).0, expected);
    }
    let (kind, _) = login_fails(metadata(|d| {
        d["token_endpoint"] = json!("http://example.com/token");
    }));
    assert_eq!(kind, "url_rejected");
}

#[test]
fn a_server_that_lists_no_auth_methods_still_logs_in() {
    let server = OAuthServer::start(metadata(|d| {
        d.as_object_mut()
            .unwrap()
            .remove("token_endpoint_auth_methods_supported");
    }));
    let h = probed(&server, unauthorized(&server), "");
    assert_eq!(
        reply(&run_watched(&h, &["login", "demo"], Act::Wait))["logged_in"],
        true
    );
}

#[test]
fn a_legacy_server_uses_its_root_metadata() {
    let server = OAuthServer::start(legacy(Doc::Patched(|_| {})));
    let h = probed(&server, unauthorized(&server), "");
    assert_eq!(
        reply(&run_watched(&h, &["login", "demo"], Act::Wait))["logged_in"],
        true
    );
    assert_eq!(
        server.paths(),
        ["/prm", "/metadata", "/register", "/authorize", "/token"]
    );
    assert!(!server.to("/authorize")[0].params.contains_key("scope"));
}

#[test]
fn a_legacy_server_without_metadata_gets_the_default_endpoints() {
    let server = OAuthServer::start(legacy(Doc::Status(404)));
    let h = probed(&server, refusal(401, None, None, None), "");
    assert_eq!(
        reply(&run_watched(&h, &["login", "demo"], Act::Wait))["logged_in"],
        true
    );
    assert_eq!(
        server.paths(),
        ["/prm", "/metadata", "/register", "/authorize", "/token"]
    );
}

#[test]
fn bad_legacy_metadata_fails() {
    for doc in [
        Doc::Status(500),
        Doc::Patched(|d| *d = json!("x")),
        Doc::Patched(|d| d["issuer"] = json!("http://127.0.0.1:1")),
    ] {
        let (kind, _) = login_fails(legacy(doc));
        assert!(kind == "http_status" || kind == "protocol_error", "{kind}");
    }
}

#[test]
fn a_repeated_challenge_scope_is_requested_once() {
    let server = OAuthServer::start(Script::default());
    let challenge = refusal(
        401,
        None,
        Some("read read"),
        Some(server.resource_metadata()),
    );
    let h = probed(&server, challenge, "");
    reply(&run_watched(&h, &["login", "demo"], Act::Wait));
    assert_eq!(server.to("/authorize")[0].params["scope"], "read");
}

#[test]
fn a_token_response_that_does_not_check_out_fails() {
    let (kind, _) = login_fails(Script {
        scope: Some("a\"b".to_owned()),
        ..Script::default()
    });
    assert_eq!(kind, "protocol_error");
    let (kind, _) = login_fails(Script {
        expires_in: Some(0),
        ..Script::default()
    });
    assert_eq!(kind, "protocol_error");
    let (kind, _) = login_fails(metadata(|d| {
        d["token_endpoint"] = json!("http://127.0.0.1:1/token");
    }));
    assert_eq!(kind, "network");
}
