//! Server-name, URL and header rules at their boundaries, and `${VAR}` expansion.

use mcpjump::config::validate::{
    HeaderTemplate, MAX_HEADER_VALUE_LEN, MAX_HEADERS, MAX_URL_LEN, ServerName, check_header_set,
    is_loopback, parse_server_url,
};
use mcpjump::error::ErrorKind;
use url::Url;

use crate::support::fakes::env::MapEnv;

fn name_kind(name: &str) -> Option<ErrorKind> {
    ServerName::parse(name).err().map(|error| error.kind())
}

#[test]
fn server_names_follow_the_rule() {
    for valid in ["a", "A9", "my_server-2", &"a".repeat(64)] {
        assert_eq!(name_kind(valid), None, "{valid}");
    }
    for invalid in ["", "-a", "_a", "a b", "a.b", "ü", &"a".repeat(65)] {
        assert_eq!(
            name_kind(invalid),
            Some(ErrorKind::InvalidName),
            "{invalid}"
        );
    }
    let name = ServerName::parse("demo").unwrap();
    assert_eq!(
        (name.as_str(), name.to_string()),
        ("demo", "demo".to_owned())
    );
}

fn url_error(raw: &str) -> Option<String> {
    parse_server_url(raw).err().map(|error| {
        assert_eq!(error.kind(), ErrorKind::InvalidUrl);
        error.message().to_owned()
    })
}

#[test]
fn urls_must_be_https_or_loopback_http() {
    for valid in [
        "https://example.com/mcp",
        "http://localhost:8080/mcp",
        "http://LOCALHOST/mcp",
        "http://127.0.0.1/mcp",
        "http://[::1]/mcp",
    ] {
        assert_eq!(url_error(valid), None, "{valid}");
    }
    let too_long = format!("https://e.com/{}", "a".repeat(MAX_URL_LEN - 14 + 1));
    let longest = &too_long[..MAX_URL_LEN];
    assert_eq!(url_error(longest), None);
    let cases = [
        (too_long.as_str(), "invalid URL: longer than 2048 bytes"),
        ("not a url", "invalid URL: relative URL without a base"),
        (
            "http://example.com/mcp",
            "invalid URL: http is allowed only for loopback hosts; use https",
        ),
        (
            "ftp://example.com/",
            "invalid URL: unsupported scheme \"ftp\"; use https",
        ),
        (
            "https://user@example.com/",
            "invalid URL: credentials in the URL are not allowed; use a header",
        ),
        (
            "https://:pw@example.com/",
            "invalid URL: credentials in the URL are not allowed; use a header",
        ),
        (
            "https://example.com/#x",
            "invalid URL: a fragment (#...) is not allowed",
        ),
    ];
    for (raw, message) in cases {
        assert_eq!(url_error(raw).as_deref(), Some(message), "{raw}");
    }
}

#[test]
fn loopback_needs_a_loopback_host() {
    assert!(!is_loopback(&Url::parse("data:text/plain,x").unwrap()));
    assert!(!is_loopback(&Url::parse("http://10.0.0.1/").unwrap()));
    assert!(!is_loopback(&Url::parse("http://[::2]/").unwrap()));
}

fn header_error(name: &str, value: &str) -> Option<String> {
    HeaderTemplate::parse(name, value).err().map(|error| {
        assert_eq!(error.kind(), ErrorKind::InvalidHeader);
        error.message().to_owned()
    })
}

#[test]
fn header_names_and_values_within_the_rules_parse() {
    let longest_value = "v".repeat(MAX_HEADER_VALUE_LEN);
    for (name, value) in [
        ("X-Key", "a\tb"),
        ("!#$%&'*+-.^_`|~", "x"),
        ("X", longest_value.as_str()),
    ] {
        assert_eq!(header_error(name, value), None, "{name}");
    }
    assert_eq!(header_error(&"n".repeat(256), "x"), None);
}

/// The error for a malformed header name, which is never echoed.
const NAME_RULE: &str = "invalid header name: use 1 to 256 letters, digits or !#$%&'*+-.^_`|~";

#[test]
fn header_rule_violations_are_named() {
    let too_long = "v".repeat(MAX_HEADER_VALUE_LEN + 1);
    let cases = [
        ("", "x", NAME_RULE),
        ("Bearer secret_SENTINEL", "x", NAME_RULE),
        (
            "Host",
            "x",
            "invalid header \"Host\": reserved; mcpjump sets this header itself",
        ),
        (
            "Mcp-Session-Id",
            "x",
            "invalid header \"Mcp-Session-Id\": reserved; mcpjump sets this header itself",
        ),
        (
            "X",
            too_long.as_str(),
            "invalid header \"X\": value longer than 8192 bytes",
        ),
        (
            "X",
            "a\nb",
            "invalid header \"X\": value contains a control character",
        ),
        (
            "X",
            "${lower}",
            "invalid header \"X\": bad variable reference: \"lower\" is not a variable name; use [A-Z0-9_]+",
        ),
        (
            "X",
            "${}",
            "invalid header \"X\": bad variable reference: \"\" is not a variable name; use [A-Z0-9_]+",
        ),
    ];
    for (name, value, message) in cases {
        assert_eq!(
            header_error(name, value).as_deref(),
            Some(message),
            "{name}"
        );
    }
    assert_eq!(
        header_error(&"n".repeat(257), "x").as_deref(),
        Some(NAME_RULE)
    );
}

#[test]
fn header_arguments_split_on_the_first_colon() {
    let header = HeaderTemplate::parse_arg(" X-Key :  a:b ").unwrap();
    assert_eq!((header.name(), header.raw_value()), ("X-Key", "a:b"));
    let error = HeaderTemplate::parse_arg("Authorization Bearer secret_SENTINEL").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidHeader);
    assert_eq!(
        error.message(),
        "invalid header argument: expected \"Name: value\""
    );
}

fn headers(count: usize) -> Vec<HeaderTemplate> {
    (0..count)
        .map(|index| HeaderTemplate::parse(&format!("X-{index}"), "v").unwrap())
        .collect()
}

#[test]
fn header_sets_are_bounded_and_unique() {
    assert_eq!(check_header_set(&headers(MAX_HEADERS)), Ok(()));
    let error = check_header_set(&headers(MAX_HEADERS + 1)).unwrap_err();
    assert_eq!(error.message(), "too many headers: at most 32");
    let duplicate = [
        HeaderTemplate::parse("X-Key", "a").unwrap(),
        HeaderTemplate::parse("x-key", "b").unwrap(),
    ];
    let error = check_header_set(&duplicate).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidHeader);
    assert_eq!(
        error.message(),
        "invalid header \"x-key\": given more than once"
    );
}

#[test]
fn values_expand_variables_and_defaults() {
    let env = MapEnv::default().with("TOKEN_2", "t0k").with("EMPTY", "");
    let header = HeaderTemplate::parse(
        "Authorization",
        "Bearer ${TOKEN_2}${EMPTY}/${MISSING:-dflt}$",
    )
    .unwrap();
    assert_eq!(header.expand(&env).unwrap(), "Bearer t0k/dflt$");
}

#[test]
fn a_missing_variable_is_an_error_never_empty() {
    let header = HeaderTemplate::parse("X-Key", "${MISSING}").unwrap();
    let error = header.expand(&MapEnv::default()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::MissingEnvVar);
    assert_eq!(
        error.message(),
        "environment variable MISSING (used by header X-Key) is not set"
    );
}

#[test]
fn expanded_values_are_checked_again() {
    let header = HeaderTemplate::parse("X-Key", "${VALUE}").unwrap();
    let error = header
        .expand(&MapEnv::default().with("VALUE", "a\r\nInjected: 1"))
        .unwrap_err();
    assert_eq!(
        error.message(),
        "invalid header \"X-Key\": value contains a control character"
    );
    let long = "v".repeat(MAX_HEADER_VALUE_LEN + 1);
    let error = header
        .expand(&MapEnv::default().with("VALUE", &long))
        .unwrap_err();
    assert_eq!(
        error.message(),
        "invalid header \"X-Key\": value longer than 8192 bytes"
    );
}
