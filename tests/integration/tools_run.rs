//! `tools` and `run` in-process, against a fake connector and session.

use std::time::Duration;

use mcpjump::config::model::{Generation, Transport};
use mcpjump::error::{Error, ErrorKind};
use mcpjump::mcp::session::ToolResult;
use serde_json::{Value, json};
use tokio::time::Instant;

use crate::support::fakes::connector::{FakeConnector, FakeSession, Log, tool};
use crate::support::fakes::terminal::ScriptedTerminal;
use crate::support::{Harness, Outcome};

const CONFIG: &str = "[limits]\nmax_params_bytes = 1024\n\n\
    [servers.demo]\nurl = \"https://a.example/mcp\"\nheaders = { X-Key = \"${KEY}\" }\n";

fn object_schema() -> Value {
    json!({"type": "object", "properties": {"n": {"type": "integer"}}})
}

/// A harness with server `demo` and `KEY` set, connected to `session`.
fn harness(session: FakeSession) -> (Harness, Log) {
    let mut h = Harness::new();
    h.write_config(CONFIG);
    h.env = h.env.clone().with("KEY", "k1");
    let log = session.log();
    h.connector = FakeConnector::session(session, Generation::Modern);
    (h, log)
}

fn entries(log: &Log) -> Vec<String> {
    log.lock().unwrap().clone()
}

fn ok(value: Value) -> ToolResult {
    ToolResult {
        value,
        is_error: false,
    }
}

fn warning(outcome: &Outcome) -> Value {
    serde_json::from_str(&outcome.err).unwrap()
}

#[test]
fn tools_lists_summaries_and_saves_the_generation() {
    let full = json!({"name": "a", "inputSchema": {}, "outputSchema": {}, "_meta": {"x": 1}});
    let session = FakeSession::default()
        .page(&[full], Some("c1"))
        .page(&[tool("b", &json!({}))], None);
    let (h, log) = harness(session);
    let listed = h.run(&["tools", "demo"]);
    assert_eq!(
        listed.json(),
        json!([
            {"name": "a", "inputSchema": {}},
            {"name": "b", "description": "b tool", "inputSchema": {}},
        ])
    );
    assert_eq!(entries(&log), ["list ", "list c1", "close"]);
    assert!(h.config_text().contains("generation = \"modern\""));
    let target = h.connector.targets.lock().unwrap()[0].clone();
    assert_eq!(target.url.as_str(), "https://a.example/mcp");
    assert_eq!(target.transport, Transport::Http);
    assert_eq!(target.generation, None);
    assert_eq!(target.headers, [("X-Key".to_owned(), "k1".to_owned())]);
    assert_eq!(target.limits.max_params_bytes, 1024);
    let budget = target.deadline - Instant::now();
    assert!(budget > Duration::from_secs(55) && budget <= Duration::from_secs(60));
}

#[test]
fn a_known_generation_is_tried_first_and_not_saved_again() {
    let session = FakeSession::default().page(&[], None);
    let (mut h, _log) = harness(session);
    let config = format!("{CONFIG}generation = \"legacy_streamable\"\n");
    h.write_config(&config);
    h.connector = FakeConnector::session(
        FakeSession::default().page(&[], None),
        Generation::LegacyStreamable,
    );
    assert_eq!(h.run(&["tools", "demo"]).json(), json!([]));
    let target = h.connector.targets.lock().unwrap()[0].clone();
    assert_eq!(target.generation, Some(Generation::LegacyStreamable));
    assert_eq!(h.config_text(), config);
}

#[test]
fn one_tool_shows_its_whole_definition_and_stops_paging() {
    let full = json!({"name": "a", "inputSchema": {}, "outputSchema": {"type": "object"}});
    let session = FakeSession::default().page(std::slice::from_ref(&full), Some("more"));
    let (h, log) = harness(session);
    assert_eq!(h.run(&["tools", "demo", "a"]).json(), full);
    assert_eq!(entries(&log), ["list ", "close"]);
}

#[test]
fn an_unknown_tool_is_a_usage_error() {
    let session = FakeSession::default().page(&[tool("a", &json!({}))], None);
    let (h, log) = harness(session);
    let missing = h.run(&["tools", "demo", "b"]);
    assert_eq!(missing.code, 2);
    assert_eq!(missing.error_kind(), "unknown_tool");
    assert!(missing.err.contains("see `mcpjump tools demo`"));
    assert_eq!(entries(&log), ["list ", "close"]);
}

#[test]
fn tools_with_invalid_names_are_counted_not_named() {
    let bad = tool("bad name!", &json!({}));
    let session = FakeSession::default().page(&[bad, tool("a", &json!({}))], None);
    let (h, _log) = harness(session);
    let listed = h.run(&["tools", "demo"]);
    assert_eq!(listed.code, 0);
    assert_eq!(
        warning(&listed),
        json!({"warning": {"message": "skipped 1 tools with invalid names"}})
    );
    let tools: Value = serde_json::from_str(&listed.out).unwrap();
    assert_eq!(tools[0]["name"], "a");
}

#[test]
fn warnings_render_as_text_with_text_output() {
    let session = FakeSession::default().page(&[tool("bad name!", &json!({}))], None);
    let (h, _log) = harness(session);
    let listed = h.run(&["-o", "text", "tools", "demo"]);
    assert_eq!(listed.code, 0);
    assert_eq!(listed.err, "warning: skipped 1 tools with invalid names\n");
}

#[test]
fn a_failed_generation_save_is_a_warning() {
    let removed = "[servers.other]\nurl = \"https://b.example/mcp\"\n";
    for (config, cause) in [("not = [toml", "config"), (removed, "no server named")] {
        let (mut h, _log) = harness(FakeSession::default());
        let session = FakeSession::default().page(&[], None);
        h.connector =
            FakeConnector::session(session, Generation::Sse).rewriting(h.config_path(), config);
        let listed = h.run(&["tools", "demo"]);
        assert_eq!((listed.code, listed.out.as_str()), (0, "[]\n"));
        let message = warning(&listed)["warning"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(message.starts_with("could not save the detected protocol generation: "));
        assert!(message.contains(cause), "{message}");
    }
}

#[test]
fn each_generation_is_saved_by_name() {
    let generations = [
        (Generation::Modern, "modern"),
        (Generation::LegacyStreamable, "legacy_streamable"),
        (Generation::Sse, "sse"),
    ];
    for (generation, name) in generations {
        let (mut h, _log) = harness(FakeSession::default());
        h.connector = FakeConnector::session(FakeSession::default().page(&[], None), generation);
        assert_eq!(h.run(&["tools", "demo"]).json(), json!([]));
        assert!(
            h.config_text()
                .contains(&format!("generation = \"{name}\""))
        );
    }
}

#[test]
fn failures_before_connecting_do_not_connect() {
    let (h, _log) = harness(FakeSession::default());
    assert_eq!(h.run(&["tools", "Bad Name"]).error_kind(), "invalid_name");
    assert_eq!(h.run(&["tools", "other"]).error_kind(), "unknown_server");
    assert_eq!(
        h.run(&["run", "Bad Name", "t"]).error_kind(),
        "invalid_name"
    );
    let mut unset = Harness::new();
    unset.write_config(CONFIG);
    unset.connector = FakeConnector::default();
    assert_eq!(
        unset.run(&["tools", "demo"]).error_kind(),
        "missing_env_var"
    );
    assert_eq!(h.connector.connects() + unset.connector.connects(), 0);
}

#[test]
fn connect_and_listing_errors_are_reported() {
    for args in [&["tools", "demo"][..], &["run", "demo", "t"]] {
        let (mut h, _log) = harness(FakeSession::default());
        h.connector = FakeConnector::answer(Err(Error::new(ErrorKind::Network, "refused")));
        assert_eq!(h.run(args).error_kind(), "network");
    }
    for args in [&["tools", "demo"][..], &["tools", "demo", "t"]] {
        let bad = Error::new(ErrorKind::ProtocolError, "bad");
        let (h, log) = harness(FakeSession::default().page_error(bad));
        let listed = h.run(args);
        assert_eq!(
            (listed.code, listed.error_kind()),
            (4, "protocol_error".to_owned())
        );
        assert_eq!(entries(&log), ["list ", "close"]);
    }
}

#[test]
fn run_calls_the_tool_with_empty_params_by_default() {
    let session = FakeSession::default()
        .page(&[tool("t", &object_schema())], None)
        .call(Ok(ok(json!({"content": []}))));
    let (h, log) = harness(session);
    assert_eq!(h.run(&["run", "demo", "t"]).json(), json!({"content": []}));
    assert_eq!(entries(&log), ["list ", "call t {}", "close"]);
    let target = h.connector.targets.lock().unwrap()[0].clone();
    let budget = target.deadline - Instant::now();
    assert!(budget > Duration::from_secs(115) && budget <= Duration::from_secs(120));
}

#[test]
fn run_passes_inline_params_under_the_given_timeout() {
    let session = FakeSession::default()
        .page(&[tool("t", &object_schema())], None)
        .call(Ok(ok(json!({}))));
    let (h, log) = harness(session);
    let ran = h.run(&["run", "demo", "t", r#"{"n": 3}"#, "--timeout", "7"]);
    assert_eq!(ran.json(), json!({}));
    assert_eq!(entries(&log)[1], r#"call t {"n":3}"#);
    let target = h.connector.targets.lock().unwrap()[0].clone();
    let budget = target.deadline - Instant::now();
    assert!(budget > Duration::from_secs(6) && budget <= Duration::from_secs(7));
}

#[test]
fn run_reads_params_from_stdin_with_a_dash() {
    let session = FakeSession::default()
        .page(&[tool("t", &object_schema())], None)
        .call(Ok(ok(json!({}))));
    let (mut h, log) = harness(session);
    // What a shell heredoc delivers: apostrophes and a trailing newline.
    let heredoc = "{\n  \"q\": \"it's Bob's\"\n}\n";
    h.terminal = ScriptedTerminal::new(Ok(heredoc.to_owned()));
    assert_eq!(h.run(&["run", "demo", "t", "-"]).json(), json!({}));
    assert_eq!(entries(&log)[1], r#"call t {"q":"it's Bob's"}"#);
    assert_eq!(
        *h.terminal.reads.lock().unwrap(),
        [(1024, Duration::from_secs(30))]
    );
}

#[test]
fn bad_params_fail_before_connecting() {
    let (mut h, _log) = harness(FakeSession::default());
    let big = format!(r#"{{"s": "{}"}}"#, "x".repeat(1024));
    let deep = format!(
        "{}{}",
        "{\"a\":".repeat(70),
        "1".to_owned() + &"}".repeat(70)
    );
    for params in [big.as_str(), "{", "[1]", deep.as_str()] {
        let failed = h.run(&["run", "demo", "t", params]);
        assert_eq!(
            (failed.code, failed.error_kind()),
            (2, "invalid_params".to_owned())
        );
    }
    let not_json = h.run(&["run", "demo", "t", "{secret"]);
    assert!(!not_json.err.contains("secret"));
    h.terminal = ScriptedTerminal::new(Err(Error::new(ErrorKind::InvalidParams, "stdin")));
    assert_eq!(
        h.run(&["run", "demo", "t", "-"]).error_kind(),
        "invalid_params"
    );
    assert_eq!(h.connector.connects(), 0);
}

#[test]
fn params_that_miss_the_schema_are_not_sent() {
    let session = FakeSession::default().page(&[tool("t", &object_schema())], None);
    let (h, log) = harness(session);
    let failed = h.run(&["run", "demo", "t", r#"{"n": "x"}"#]);
    assert_eq!(failed.error_kind(), "invalid_params");
    let error: Value = serde_json::from_str(&failed.err).unwrap();
    assert_eq!(error["error"]["path"], "/n");
    assert_eq!(entries(&log), ["list ", "close"]);
}

#[test]
fn a_tool_without_a_schema_takes_any_object() {
    let session = FakeSession::default()
        .page(&[json!({"name": "t"})], None)
        .call(Ok(ok(json!({}))));
    let (h, _log) = harness(session);
    assert_eq!(
        h.run(&["run", "demo", "t", r#"{"any": [1]}"#]).json(),
        json!({})
    );
}

#[test]
fn a_tool_error_prints_the_result_and_exits_one() {
    let result = json!({"content": [], "isError": true});
    let session = FakeSession::default()
        .page(&[tool("t", &json!({}))], None)
        .call(Ok(ToolResult {
            value: result.clone(),
            is_error: true,
        }));
    let (h, _log) = harness(session);
    let ran = h.run(&["run", "demo", "t"]);
    assert_eq!((ran.code, ran.err.as_str()), (1, ""));
    assert_eq!(serde_json::from_str::<Value>(&ran.out).unwrap(), result);
}

#[test]
fn a_lost_call_says_execution_is_unknown() {
    let lost = Error::new(ErrorKind::DeliveryUnknown, "reset");
    let session = FakeSession::default()
        .page(&[tool("t", &json!({}))], None)
        .call(Err(lost));
    let (h, log) = harness(session);
    let ran = h.run(&["run", "demo", "t"]);
    assert_eq!(ran.code, 4);
    let error: Value = serde_json::from_str(&ran.err).unwrap();
    assert_eq!(error["error"]["execution"], "unknown");
    assert_eq!(entries(&log), ["list ", "call t {}", "close"]);
}

#[test]
fn run_keeps_listing_warnings_and_rejects_unknown_tools() {
    let session = FakeSession::default()
        .page(
            &[tool("bad name!", &json!({})), tool("t", &json!({}))],
            None,
        )
        .call(Ok(ok(json!({}))));
    let (h, _log) = harness(session);
    let ran = h.run(&["run", "demo", "t"]);
    assert_eq!((ran.code, ran.out.as_str()), (0, "{}\n"));
    assert_eq!(
        warning(&ran)["warning"]["message"],
        "skipped 1 tools with invalid names"
    );
    let (h, _log) = harness(FakeSession::default().page(&[], None));
    assert_eq!(h.run(&["run", "demo", "t"]).error_kind(), "unknown_tool");
}

#[test]
fn an_oversized_page_containing_the_wanted_tool_never_calls_it() {
    let definitions: Vec<Value> = (0..4)
        .map(|index| tool(&format!("t{index}"), &json!({})))
        .collect();
    let session = FakeSession::default().page(&definitions, Some("unused"));
    let (h, log) = harness(session);
    h.write_config("[limits]\nmax_tools = 3\n[servers.demo]\nurl = \"https://example.com/mcp\"\n");
    let outcome = h.run(&["run", "demo", "t0"]);
    assert_eq!(outcome.code, 4);
    assert_eq!(outcome.error_kind(), "tool_list_limit");
    assert_eq!(entries(&log), ["list ", "close"]);
}
