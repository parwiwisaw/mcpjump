//! Records round-trip, and anything mcpjump could not have written is
//! rejected on read.

use mcpjump::error::ErrorKind;
use mcpjump::store::RecordKind;
use mcpjump::store::record::{
    self, Record, RegistrationMethod, RegistrationRecord, TokenEndpointAuth, TokenRecord,
};
use serde_json::{Value, json};

use crate::store_contract::key;

fn tokens() -> Value {
    json!({
        "access_token": "at-123",
        "refresh_token": "rt-456",
        "expires_at": 1_900_000_000,
        "token_type": "Bearer",
        "scopes": ["mcp:tools", "offline_access"],
        "issuer": "https://auth.example.com/",
        "resource": "https://mcp.example.com/mcp",
        "client_id": "client-1",
        "token_endpoint": "https://auth.example.com/token",
        "pending_scopes": ["mcp:admin"],
    })
}

fn registration() -> Value {
    json!({
        "issuer": "https://auth.example.com/",
        "client_id": "client-1",
        "client_secret": "s3cret",
        "token_endpoint_auth_method": "client_secret_basic",
        "redirect_uri": "http://127.0.0.1:53682/callback",
        "method": "dynamic",
    })
}

fn decode<R: Record>(value: &Value) -> Result<R, mcpjump::error::Error> {
    let key = key("demo", RecordKind::Tokens);
    record::decode(&key, value.to_string().as_bytes())
}

fn with(mut value: Value, field: &str, replacement: Value) -> Value {
    value[field] = replacement;
    value
}

#[test]
fn records_round_trip() {
    let tokens: TokenRecord = decode(&tokens()).unwrap();
    let key = key("demo", RecordKind::Tokens);
    assert_eq!(
        record::decode::<TokenRecord>(&key, &record::encode(&tokens)).unwrap(),
        tokens
    );
    let registration: RegistrationRecord = decode(&registration()).unwrap();
    assert_eq!(registration.method, RegistrationMethod::Dynamic);
    let encoded = record::encode(&registration);
    assert_eq!(
        record::decode::<RegistrationRecord>(&key, &encoded).unwrap(),
        registration
    );
}

#[test]
fn optional_token_fields_may_be_absent() {
    let minimal = with(
        with(tokens(), "refresh_token", Value::Null),
        "expires_at",
        Value::Null,
    );
    let minimal = with(minimal, "scopes", json!([]));
    let minimal = with(minimal, "token_type", json!("bearer"));
    let mut minimal = minimal;
    minimal.as_object_mut().unwrap().remove("pending_scopes");
    let decoded = decode::<TokenRecord>(&minimal).unwrap();
    assert_eq!(decoded.pending_scopes, Vec::<String>::new());
    let key = key("demo", RecordKind::Tokens);
    let text = String::from_utf8(record::encode(&decoded)).unwrap();
    assert!(!text.contains("pending_scopes"));
    assert_eq!(
        record::decode::<TokenRecord>(&key, text.as_bytes()).unwrap(),
        decoded
    );
}

#[test]
fn loopback_urls_may_be_plain_http() {
    let loopback = with(tokens(), "issuer", json!("http://127.0.0.1:8080/"));
    decode::<TokenRecord>(&with(loopback, "resource", json!("http://localhost/mcp"))).unwrap();
}

#[test]
fn a_public_client_has_no_secret() {
    let public = with(registration(), "client_secret", Value::Null);
    for method in ["preregistered", "metadata_document", "dynamic"] {
        let public = with(
            with(public.clone(), "token_endpoint_auth_method", json!("none")),
            "method",
            json!(method),
        );
        decode::<RegistrationRecord>(&public).unwrap();
    }
    let post = with(
        registration(),
        "token_endpoint_auth_method",
        json!("client_secret_post"),
    );
    let post: RegistrationRecord = decode(&post).unwrap();
    assert_eq!(
        post.token_endpoint_auth_method,
        TokenEndpointAuth::ClientSecretPost
    );
}

#[test]
fn a_token_record_mcpjump_could_not_have_written_is_damaged() {
    let long = "a".repeat(16 * 1024 + 1);
    let many: Vec<String> = (0..65).map(|i| format!("s{i}")).collect();
    let cases = [
        with(tokens(), "access_token", json!("")),
        with(tokens(), "access_token", json!("has space")),
        with(tokens(), "access_token", json!(long)),
        with(tokens(), "refresh_token", json!("tab\there")),
        with(tokens(), "token_type", json!("MAC")),
        with(tokens(), "scopes", json!(many)),
        with(tokens(), "scopes", json!([""])),
        with(tokens(), "scopes", json!(["a b"])),
        with(tokens(), "scopes", json!(["a\"b"])),
        with(tokens(), "scopes", json!(["a\\b"])),
        with(tokens(), "scopes", json!(["x".repeat(257)])),
        with(tokens(), "client_id", json!("")),
        with(tokens(), "issuer", json!("not a url")),
        with(tokens(), "issuer", json!("http://auth.example.com/")),
        with(tokens(), "issuer", json!("ftp://auth.example.com/")),
        with(tokens(), "resource", json!("http://mcp.example.com/mcp")),
        with(
            tokens(),
            "token_endpoint",
            json!("http://auth.example.com/token"),
        ),
        with(tokens(), "pending_scopes", json!(["a b"])),
        with(tokens(), "pending_scopes", json!(vec!["s".repeat(200); 6])),
        with(tokens(), "extra", json!(1)),
        json!([]),
    ];
    for case in cases {
        let error = decode::<TokenRecord>(&case).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialInvalid, "{case}");
    }
}

#[test]
fn a_registration_record_mcpjump_could_not_have_written_is_damaged() {
    let cases = [
        with(registration(), "client_secret", Value::Null),
        with(
            with(registration(), "token_endpoint_auth_method", json!("none")),
            "client_secret",
            json!("s"),
        ),
        with(registration(), "client_secret", json!("")),
        with(registration(), "client_id", json!("")),
        with(
            registration(),
            "redirect_uri",
            json!("https://127.0.0.1/callback"),
        ),
        with(
            registration(),
            "redirect_uri",
            json!("http://localhost:1/callback"),
        ),
        with(
            registration(),
            "redirect_uri",
            json!("http://127.0.0.1:1/other"),
        ),
        with(
            registration(),
            "redirect_uri",
            json!("http://127.0.0.1/callback"),
        ),
        with(
            registration(),
            "redirect_uri",
            json!("http://127.0.0.1:1/callback?x=1"),
        ),
        with(
            registration(),
            "redirect_uri",
            json!("http://127.0.0.1:1/callback#x"),
        ),
        with(registration(), "issuer", json!("http://auth.example.com/")),
        with(registration(), "method", json!("other")),
        with(
            registration(),
            "token_endpoint_auth_method",
            json!("private_key_jwt"),
        ),
        with(registration(), "extra", json!(1)),
    ];
    for case in cases {
        let error = decode::<RegistrationRecord>(&case).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialInvalid, "{case}");
    }
}
