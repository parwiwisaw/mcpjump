//! The CLI run in-process: argument parsing, commands, output and exit codes.

use serde_json::json;

use crate::support::fakes::env::MapEnv;
use crate::support::{BrokenWriter, ClosedPipe, Harness};

const URL: &str = "https://example.com/mcp";

#[test]
fn add_list_get_remove_round_trip() {
    let h = Harness::new();
    let added = h.run(&[
        "add",
        "-H",
        "X-Key: ${KEY:-dev}",
        "--client-id",
        "cid",
        "--callback-port",
        "8123",
        "-s",
        "user",
        "demo",
        URL,
    ]);
    assert_eq!(
        added.json(),
        json!({"name": "demo", "url": URL, "transport": "http"})
    );
    assert!(h.config_text().starts_with("# mcpjump configuration."));
    assert!(h.config_text().ends_with(
        "\n[servers.demo]\nurl = \"https://example.com/mcp\"\ntransport = \"http\"\n\
         headers = { X-Key = \"${KEY:-dev}\" }\nclient_id = \"cid\"\ncallback_port = 8123\n"
    ));
    assert_eq!(
        h.run(&["list"]).json(),
        json!([{"name": "demo", "url": URL, "transport": "http", "generation": null, "credentials": null}])
    );
    assert_eq!(
        h.run(&["get", "demo"]).json(),
        json!({
            "name": "demo", "url": URL, "transport": "http", "generation": null,
            "headers": {"X-Key": "[redacted]"}, "client_id": "cid",
            "callback_port": 8123, "credentials": null,
        })
    );
    assert_eq!(
        h.run(&["remove", "demo"]).json(),
        json!({"removed": "demo"})
    );
    assert_eq!(h.run(&["list"]).json(), json!([]));
}

#[test]
fn a_fresh_install_lists_nothing_and_writes_nothing() {
    let h = Harness::new();
    assert_eq!(h.run(&["list"]).json(), json!([]));
    assert!(!h.config_path().exists());
}

#[test]
fn edits_keep_the_users_comments() {
    let h = Harness::new();
    h.write_config("# keep me\n[settings]\noutput = \"json\" # and me\n");
    h.run(&["add", "-t", "sse", "demo", URL]).json();
    assert_eq!(
        h.config_text(),
        "# keep me\n[settings]\noutput = \"json\" # and me\n\n\
         [servers.demo]\nurl = \"https://example.com/mcp\"\ntransport = \"sse\"\n"
    );
}

#[test]
fn text_output_comes_from_the_flag_or_the_config() {
    let h = Harness::new();
    h.run(&["add", "demo", URL]).json();
    let flag = h.run(&["-o", "text", "get", "demo"]);
    assert_eq!(flag.code, 0);
    assert!(
        flag.out
            .starts_with("name: demo\nurl: https://example.com/mcp\n"),
        "{}",
        flag.out
    );
    h.write_config(
        &h.config_text()
            .replace("output = \"json\"", "output = \"text\""),
    );
    let listed = h.run(&["list"]);
    let lines: Vec<&str> = listed.out.lines().map(str::trim_end).collect();
    assert_eq!(
        lines,
        [
            "NAME  URL                      TRANSPORT  GENERATION  CREDENTIALS",
            "demo  https://example.com/mcp  http       -           -"
        ]
    );
    let failed = h.run(&["get", "nope"]);
    assert_eq!(
        (failed.code, failed.err.as_str()),
        (2, "error: no server named \"nope\"; see `mcpjump list`\n")
    );
    assert_eq!(h.run(&["-o", "json", "list"]).json()[0]["name"], "demo");
}

#[test]
fn argument_errors_have_kinds_and_exit_two() {
    let h = Harness::new();
    h.run(&["add", "demo", URL]).json();
    let cases: [(&[&str], &str); 9] = [
        (&["add", "demo", URL], "server_exists"),
        (&["add", "a.b", URL], "invalid_name"),
        (&["add", "x", "http://example.com"], "invalid_url"),
        (&["add", "-H", "no colon", "x", URL], "invalid_header"),
        (
            &["add", "-H", "X-A: 1", "-H", "x-a: 2", "x", URL],
            "invalid_header",
        ),
        (&["add", "--client-id", "", "x", URL], "usage"),
        (&["get", "nope"], "unknown_server"),
        (&["remove", "nope"], "unknown_server"),
        (&["get", "a b"], "invalid_name"),
    ];
    for (args, kind) in cases {
        let outcome = h.run(args);
        assert_eq!(
            (outcome.code, outcome.error_kind().as_str()),
            (2, kind),
            "{args:?}"
        );
    }
    let outcome = h.run(&["remove", "a b"]);
    assert_eq!(outcome.error_kind(), "invalid_name");
}

#[test]
fn clap_errors_exit_two_on_stderr() {
    let h = Harness::new();
    for args in [&["add", "-s", "project", "x", URL][..], &[], &["bogus"]] {
        let outcome = h.run(args);
        assert_eq!((outcome.code, outcome.out.as_str()), (2, ""), "{args:?}");
        assert_ne!(outcome.err, "");
    }
}

#[test]
fn help_and_version_go_to_stdout() {
    let h = Harness::new();
    let help = h.run(&["--help"]);
    assert_eq!((help.code, help.err.as_str()), (0, ""));
    assert!(help.out.contains("Usage: mcpjump"), "{}", help.out);
    let version = h.run(&["--version"]);
    assert_eq!(
        version.out,
        format!("mcpjump {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn a_broken_config_fails_every_command_with_exit_five() {
    let h = Harness::new();
    h.write_config("[settings]\noutput = \"text\"\nbogus = 1\n");
    let outcome = h.run(&["list"]);
    assert_eq!(
        (outcome.code, outcome.error_kind().as_str()),
        (5, "config_invalid")
    );
    let text = h.run(&["-o", "text", "list"]);
    assert!(
        text.err
            .starts_with("error: config.toml (line 3): unknown field `bogus`"),
        "{}",
        text.err
    );
}

#[test]
fn no_config_directory_is_a_config_io_error() {
    let mut h = Harness::new();
    h.env = MapEnv::default();
    let outcome = h.run(&["list"]);
    assert_eq!(
        (outcome.code, outcome.error_kind().as_str()),
        (5, "config_io")
    );
}

#[test]
fn a_reader_that_stops_early_ends_quietly() {
    let h = Harness::new();
    let mut err = Vec::new();
    assert_eq!(h.run_with(&["list"], &mut ClosedPipe, &mut err), 0);
    assert_eq!(err, Vec::<u8>::new());
}

#[test]
fn an_unwritable_stdout_is_output_io() {
    let h = Harness::new();
    let mut err = Vec::new();
    assert_eq!(h.run_with(&["list"], &mut BrokenWriter, &mut err), 5);
    let error: serde_json::Value = serde_json::from_slice(&err).unwrap();
    assert_eq!(
        error,
        json!({"error": {"kind": "output_io", "message": "cannot write output: closed"}})
    );
    let mut err = Vec::new();
    assert_eq!(h.run_with(&["--help"], &mut BrokenWriter, &mut err), 5);
    assert_eq!(err, b"error: cannot write output: closed\n");
}

#[test]
fn an_unwritable_stderr_still_sets_the_exit_code() {
    let h = Harness::new();
    let mut out = Vec::new();
    assert_eq!(h.run_with(&["get", "nope"], &mut out, &mut BrokenWriter), 2);
    assert_eq!(h.run_with(&["bogus"], &mut out, &mut BrokenWriter), 2);
    assert_eq!(
        h.run_with(&["list"], &mut BrokenWriter, &mut BrokenWriter),
        5
    );
    assert_eq!(out, Vec::<u8>::new());
}

#[test]
fn add_json_accepts_claude_code_definitions() {
    let h = Harness::new();
    let definition = r#"{"type":"streamable-http","url":"https://example.com/mcp","headers":{"X-Key":"${KEY}"},"timeout":5,"alwaysLoad":true,"oauth":{"clientId":"cid","callbackPort":9000}}"#;
    assert_eq!(
        h.run(&["add-json", "a", definition]).json(),
        json!({"name": "a", "url": URL, "transport": "http"})
    );
    h.run(&[
        "add-json",
        "b",
        r#"{"type":"http","url":"https://example.com/mcp"}"#,
    ])
    .json();
    h.run(&[
        "add-json",
        "c",
        r#"{"type":"sse","url":"https://example.com/sse"}"#,
    ])
    .json();
    let a = h.run(&["get", "a"]).json();
    assert_eq!(
        (a["client_id"].clone(), a["callback_port"].clone()),
        (json!("cid"), json!(9000))
    );
    assert_eq!(a["headers"], json!({"X-Key": "[redacted]"}));
    assert_eq!(h.run(&["get", "c"]).json()["transport"], "sse");
}

/// Rejected definitions: the JSON, the error kind and the message.
const REJECTED_DEFINITIONS: [(&str, &str, &str); 7] = [
    (
        "not json",
        "invalid_definition",
        "invalid server definition at line 1 column 2",
    ),
    (
        r#"{"type":"stdio","url":"x"}"#,
        "invalid_definition",
        "unsupported type; mcpjump supports http, streamable-http and sse",
    ),
    (
        r#"{"type":"http","url":"https://e.com","headersHelper":"x"}"#,
        "invalid_definition",
        "headersHelper is not supported by mcpjump",
    ),
    (
        r#"{"type":"http","url":"https://e.com","oauth":{"authServerMetadataUrl":"x"}}"#,
        "invalid_definition",
        "oauth.authServerMetadataUrl is not supported by mcpjump",
    ),
    (
        r#"{"type":"http","url":"https://e.com","oauth":{"scopes":"x"}}"#,
        "invalid_definition",
        "oauth.scopes is not supported by mcpjump",
    ),
    (
        r#"{"type":"http","url":"https://e.com","headers":{"Host":"x"}}"#,
        "invalid_header",
        "invalid header \"Host\": reserved; mcpjump sets this header itself",
    ),
    (
        r#"{"type":"http","url":"http://e.com"}"#,
        "invalid_url",
        "invalid URL: http is allowed only for loopback hosts; use https",
    ),
];

#[test]
fn add_json_rejects_what_mcpjump_cannot_honor() {
    let h = Harness::new();
    for (definition, kind, message) in REJECTED_DEFINITIONS {
        let outcome = h.run(&["add-json", "a", definition]);
        let error: serde_json::Value = serde_json::from_str(&outcome.err).unwrap();
        assert_eq!(
            (
                outcome.code,
                &error["error"]["kind"],
                &error["error"]["message"]
            ),
            (2, &json!(kind), &json!(message)),
            "{definition}"
        );
    }
    let unknown = h.run(&[
        "add-json",
        "a",
        r#"{"type":"http","url":"https://e.com","command":"x"}"#,
    ]);
    assert_eq!(unknown.error_kind(), "invalid_definition");
    assert_eq!(
        h.run(&[
            "add-json",
            "a.b",
            r#"{"type":"http","url":"https://e.com"}"#
        ])
        .error_kind(),
        "invalid_name"
    );
    assert!(!h.config_path().exists());
}

#[test]
fn add_json_errors_never_echo_supplied_values() {
    let h = Harness::new();
    let definitions = [
        r#"{"type":"http","url":"https://example.com/mcp","headers":"Bearer secret_SENTINEL"}"#,
        r#"{"type":"http","url":"https://example.com/mcp","headers":{"Authorization":["Bearer secret_SENTINEL"]}}"#,
        r#"{"type":"http","url":"https://example.com/mcp","oauth":{"callbackPort":"secret_SENTINEL"}}"#,
        r#"{"type":"secret_SENTINEL","url":"https://example.com/mcp"}"#,
        r#"{"type":"http","url":"https://example.com/mcp","secret_SENTINEL":true}"#,
        r#"{"type":"http","url":"https://example.com/mcp","headers":"Bearer \"secret_SENTINEL\""}"#,
    ];
    for definition in definitions {
        for format in ["json", "text"] {
            let outcome = h.run(&["-o", format, "add-json", "a", definition]);
            assert_eq!(outcome.code, 2);
            assert_eq!(outcome.out, "");
            assert!(!outcome.err.contains("secret_SENTINEL"), "{}", outcome.err);
            assert!(outcome.err.contains("invalid_definition") || format == "text");
        }
    }
    assert!(!h.config_path().exists());
}

/// Arguments with a usage error, and whether stderr should be JSON.
const USAGE_FORMATS: [(&[&str], bool); 9] = [
    (&["bogus"], true),
    (&["-o", "json", "bogus"], true),
    (&["--output=json", "bogus"], true),
    (&["-ojson", "bogus"], true),
    (&["-o", "text", "-o", "json", "bogus"], true),
    (&["-o", "yaml", "bogus"], true),
    (&["bogus", "--", "-o", "text"], true),
    (&["bogus", "-o"], true),
    (&["-o", "text", "bogus"], false),
];

#[test]
fn usage_errors_follow_the_requested_format() {
    let h = Harness::new();
    for (args, is_json) in USAGE_FORMATS {
        let outcome = h.run(args);
        let error: serde_json::Value = serde_json::from_str(&outcome.err).unwrap_or_default();
        assert_eq!(
            (outcome.code, error["error"]["kind"] == "usage"),
            (2, is_json),
            "{args:?}: {}",
            outcome.err
        );
    }
    assert_eq!(
        h.run(&["bogus"]).err,
        "{\"error\":{\"kind\":\"usage\",\"message\":\"unrecognized subcommand 'bogus'\"}}\n"
    );
}

#[test]
fn usage_errors_fall_back_to_the_config_format() {
    let h = Harness::new();
    h.write_config("[settings]\noutput = \"text\"\n");
    let outcome = h.run(&["bogus"]);
    assert!(
        outcome
            .err
            .starts_with("error: unrecognized subcommand 'bogus'"),
        "{}",
        outcome.err
    );
    assert!(outcome.err.contains("Usage:"), "{}", outcome.err);
    h.write_config("[settings]\nbogus = 1\n");
    assert_eq!(h.run(&["bogus"]).error_kind(), "usage");
    let bare = h.run(&[]);
    assert_eq!(bare.code, 2);
    assert!(bare.err.contains("Usage: mcpjump"), "{}", bare.err);
    let missing = h.run(&["-o", "json"]);
    assert_eq!(missing.error_kind(), "usage");
}

#[cfg(unix)]
fn non_utf8() -> std::ffi::OsString {
    std::os::unix::ffi::OsStringExt::from_vec(vec![0xff])
}

#[cfg(windows)]
fn non_utf8() -> std::ffi::OsString {
    std::os::windows::ffi::OsStringExt::from_wide(&[0xD800])
}

#[test]
fn non_utf8_arguments_do_not_hide_the_format_flag() {
    let h = Harness::new();
    let deps = h.deps();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let args = ["mcpjump".into(), non_utf8(), "-o".into(), "text".into()];
    assert_eq!(mcpjump::run(args, &deps, &mut out, &mut err), 2);
    assert!(String::from_utf8(err).unwrap().starts_with("error: "));
}

#[test]
fn add_and_add_json_reject_ascii_aliases_without_store_or_config_changes() {
    use crate::store_contract::key;
    use mcpjump::store::{CredentialStore, RecordKind};

    for (existing, added) in [("Demo", "demo"), ("demo", "Demo")] {
        for command in ["add", "add-json"] {
            let h = Harness::new();
            let original =
                format!("[servers.{existing}]\nurl = \"{URL}\"\ncredentials = \"keyring\"\n");
            h.write_config(&original);
            let account = key(existing, RecordKind::Tokens);
            h.stores
                .keyring()
                .set(&account, br#"{"sentinel":"kept credentials"}"#)
                .unwrap();
            let value = if command == "add" {
                URL
            } else {
                r#"{"type":"http","url":"https://example.com/mcp"}"#
            };
            let outcome = h.run(&[command, added, value]);
            assert_eq!(
                (outcome.code, outcome.error_kind().as_str()),
                (2, "server_exists")
            );
            assert_eq!(h.config_text(), original);
            assert_eq!(h.stores.opened(), 0);
            assert_eq!(
                h.stores.keyring().get(&account).unwrap().unwrap(),
                br#"{"sentinel":"kept credentials"}"#
            );
        }
    }
}

#[test]
fn a_case_colliding_startup_config_exits_five_without_credential_access() {
    let h = Harness::new();
    let original = "[servers.Demo]\nurl = \"https://example.com/mcp\"\n\
                    [servers.demo]\nurl = \"https://example.com/mcp\"\n";
    h.write_config(original);
    for args in [
        &["list"][..],
        &["tools", "demo"],
        &["run", "Demo", "t"],
        &["remove", "Demo"],
        &["login", "demo"],
    ] {
        let outcome = h.run(args);
        assert_eq!(
            (outcome.code, outcome.error_kind().as_str()),
            (5, "config_invalid")
        );
        assert_eq!(h.config_text(), original);
        assert_eq!(h.stores.opened(), 0);
        assert_eq!(h.connector.connects(), 0);
        assert_eq!(h.browser.opens(), 0);
    }
}
