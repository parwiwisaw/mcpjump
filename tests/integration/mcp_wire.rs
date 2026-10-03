//! Wire contracts against literal JSON and SSE, independent of rmcp models.

use std::sync::Arc;
use std::time::Duration;

use mcpjump::config::limits::Limits;
use mcpjump::config::model::{Generation, Transport};
use mcpjump::mcp::connector::{Connection, Target};
use mcpjump::mcp::tools::scan;
use rmcp::model::ProtocolVersion;
use serde_json::{Value, json};

use crate::support::http::after;
use crate::support::mcp_client::{arguments, connect, target};
use crate::support::mcp_server::{answer_with_version, entries, json as model_json, streamable};
use crate::support::raw_mcp_server::{Delivery, Fixture, Step};

/// A short command deadline and one second request/idle bounds.
pub(crate) fn quick(fixture: &Fixture, generation: Option<Generation>) -> Target {
    let mut target = target(fixture.url.clone(), Transport::Http, generation);
    target.deadline = after(3_000);
    target.limits.request_timeout_secs = 1;
    target.limits.stream_idle_secs = 1;
    target
}

/// A JSON-RPC result with an explicitly scripted id.
pub(crate) fn result(id: u64, value: &Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": value}).to_string()
}

/// A JSON-RPC error; deliberately contains text that must never escape.
pub(crate) fn error(id: u64, code: i32, data: &Value) -> String {
    json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,"message":"server secret", "data":data}})
        .to_string()
}

/// A message event, framed literally without the SDK's SSE serializer.
pub(crate) fn frame(body: &str) -> String {
    format!("event: message\ndata: {body}\n\n")
}

/// A finite JSON or SSE POST response.
pub(crate) fn reply(method: &'static str, body: String, sse: bool) -> Step {
    if sse {
        Step::new(method, 200, "text/event-stream", frame(&body))
    } else {
        Step::new(method, 200, "application/json", body)
    }
}

/// An empty response with a chosen status.
pub(crate) fn status(method: &'static str, code: u16) -> Step {
    Step::new(method, code, "application/json", String::new())
}

/// A Modern discover result; the version is the wire version, not an SDK constant.
pub(crate) fn discover(id: u64) -> String {
    result(
        id,
        &json!({"resultType":"complete","ttlMs":0,"cacheScope":"private","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"serverInfo":{"name":"wire","version":"1"}}),
    )
}

/// A Legacy initialize result with a test-selected version.
pub(crate) fn initialize(id: u64, version: &str) -> String {
    result(
        id,
        &json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"wire","version":"1"}}),
    )
}

/// A minimal tool definition that the client can list and call.
fn tool(name: &str) -> Value {
    json!({"name":name,"inputSchema":{"type":"object"}})
}

/// A list result with an explicit optional cursor.
pub(crate) fn listing(id: u64) -> String {
    result(id, &json!({"tools":[tool("echo")]}))
}

/// A literal call result.
pub(crate) fn called(id: u64) -> String {
    result(
        id,
        &json!({"content":[{"type":"text","text":"ok"}],"isError":false}),
    )
}

/// Modern's sole handshake exchange.
pub(crate) fn modern(sse: bool) -> Vec<Step> {
    vec![reply("server/discover", discover(0), sse)]
}

/// Legacy Streamable's initialize and initialized exchanges, with optional session.
pub(crate) fn legacy(version: &str, sse: bool, session: bool) -> Vec<Step> {
    let mut init = reply("initialize", initialize(0, version), sse);
    if session {
        init = init.session("s1");
    }
    vec![init, status("notifications/initialized", 202)]
}

/// HTTP+SSE's GET endpoint and initialize on the GET stream.
pub(crate) fn http_sse() -> Vec<Step> {
    vec![
        Step::new(
            "GET",
            200,
            "text/event-stream",
            "event: endpoint\ndata: /messages?s=1\n\n".to_owned(),
        )
        .deliver(Delivery::Start),
        pushed("initialize", frame(&initialize(0, "2024-11-05")), false),
        status("notifications/initialized", 202),
    ]
}

/// A POST accepted while its literal reply is pushed to the GET stream.
fn pushed(method: &'static str, bytes: String, end: bool) -> Step {
    Step::new(method, 202, "application/json", bytes).deliver(Delivery::Push(end))
}

/// Labels of all received requests, including GET, DELETE and reply POSTs.
pub(crate) fn labels(fixture: &Fixture) -> Vec<String> {
    fixture
        .received()
        .iter()
        .map(|request| request.label().to_owned())
        .collect()
}

/// List and call through the real session, then explicitly close it.
pub(crate) async fn exercise(mut connection: Connection) {
    let page = connection.session.list_tools_page(None).await.unwrap();
    assert_eq!(page.tools[0].name, "echo");
    let called = connection
        .session
        .call_tool("echo", arguments())
        .await
        .unwrap();
    assert_eq!(called.value["content"][0]["text"], "ok");
    assert!(!called.is_error);
    connection.session.close().await;
}

/// Every later request must keep the initialize session id.
pub(crate) fn session_headers(fixture: &Fixture, start: usize) {
    for request in &fixture.received()[start..] {
        if request.label() == "initialize" {
            assert!(!request.headers.contains_key("mcp-session-id"));
        } else {
            assert_eq!(request.headers["mcp-session-id"], "s1");
        }
    }
}

/// Assert an error's public kind and secret-free diagnostics.
fn assert_error(error: &mcpjump::error::Error, kind: &str) {
    assert_eq!(error.kind().as_str(), kind, "{}", error.message());
    assert!(!error.message().contains("secret"));
}

/// The configurable SDK fixture retains its default and accepts each legacy version.
#[tokio::test]
async fn model_fixture_initialize_version_is_selected_per_test() {
    for version in [
        ProtocolVersion::V_2025_03_26,
        ProtocolVersion::V_2025_06_18,
        ProtocolVersion::V_2025_11_25,
    ] {
        let (url, log) = streamable(Arc::new(move |received| {
            answer_with_version(received, version.clone()).map_or_else(
                || axum::response::IntoResponse::into_response(axum::http::StatusCode::ACCEPTED),
                |message| model_json(&message),
            )
        }))
        .await;
        let connection = connect(target(
            url,
            Transport::Http,
            Some(Generation::LegacyStreamable),
        ))
        .await
        .unwrap();
        assert_eq!(connection.generation, Generation::LegacyStreamable);
        connection.session.close().await;
        assert_eq!(entries(&log), ["initialize", "notifications/initialized"]);
    }
}

/// Modern discover, list and call all accept SSE responses.
#[tokio::test]
async fn modern_discover_list_and_call_over_sse() {
    let mut steps = modern(true);
    steps.extend([
        reply("tools/list", listing(1), true),
        reply("tools/call", called(2), true),
    ]);
    let fixture = Fixture::new(steps).await;
    let connection = connect(quick(&fixture, None)).await.unwrap();
    assert_eq!(connection.generation, Generation::Modern);
    exercise(connection).await;
    fixture.finished();
    for request in fixture.received() {
        assert_eq!(request.verb, reqwest::Method::POST);
        assert_eq!(request.path, "/mcp");
        assert_eq!(request.headers["content-type"], "application/json");
        assert_eq!(
            request.headers["accept"],
            "application/json, text/event-stream"
        );
        assert_eq!(request.headers["mcp-method"], request.label());
        assert_eq!(request.headers["mcp-protocol-version"], "2026-07-28");
        assert_eq!(
            request.body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        assert!(
            request.body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
                .is_object()
        );
        assert!(!request.headers.contains_key("mcp-session-id"));
    }
    fixture.cleaned_up().await;
}

/// Transport/protocol failures, including mismatched errors, never imply legacy support.
#[tokio::test]
async fn incomplete_sse_discover_never_falls_back() {
    let bodies = [
        String::new(),
        "data: {".to_owned(),
        frame(&error(999, -32601, &Value::Null)),
    ];
    for body in bodies {
        let fixture = Fixture::new(vec![Step::new(
            "server/discover",
            200,
            "text/event-stream",
            body,
        )])
        .await;
        let failed = connect(quick(&fixture, None)).await.unwrap_err();
        assert_error(&failed, "protocol_error");
        assert_eq!(labels(&fixture), ["server/discover"]);
        fixture.finished();
    }
}

/// JSON handshake rejection codes remain server errors, not fallback signals.
#[tokio::test]
async fn modern_json_rejections_preserve_codes() {
    for code in [-32020, -32021] {
        let fixture = Fixture::new(vec![reply(
            "server/discover",
            error(0, code, &Value::Null),
            false,
        )])
        .await;
        let failed = connect(quick(&fixture, None)).await.unwrap_err();
        assert_error(&failed, "server_error");
        assert!(
            failed
                .message()
                .ends_with(&format!("JSON-RPC error {code}"))
        );
        fixture.finished();
    }
}

/// Two correlated version rejections exhaust Modern, then probe Legacy once.
#[tokio::test]
async fn modern_json_version_retry_exhausts_before_legacy() {
    let mut steps = vec![
        reply(
            "server/discover",
            error(0, -32022, &json!({"supported":["2026-07-28"]})),
            false,
        ),
        reply(
            "server/discover",
            error(1, -32022, &json!({"supported":["2026-07-28"]})),
            false,
        ),
    ];
    steps.extend(legacy("2025-11-25", false, false));
    let fixture = Fixture::new(steps).await;
    let connection = connect(quick(&fixture, None)).await.unwrap();
    assert_eq!(connection.generation, Generation::LegacyStreamable);
    connection.session.close().await;
    fixture.finished();
}

/// Each supported version works with both reply representations and session echoing.
#[tokio::test]
async fn legacy_negotiates_all_supported_versions_as_json_and_sse() {
    for version in ["2025-03-26", "2025-06-18", "2025-11-25"] {
        for sse in [false, true] {
            let mut steps = legacy(version, sse, true);
            steps.extend([
                reply("tools/list", listing(1), sse),
                reply("tools/call", called(2), sse),
                status("DELETE", 200),
            ]);
            let fixture = Fixture::new(steps).await;
            let connection = connect(quick(&fixture, Some(Generation::LegacyStreamable)))
                .await
                .unwrap();
            assert_eq!(connection.generation, Generation::LegacyStreamable);
            exercise(connection).await;
            assert_eq!(
                fixture.received()[0].body["params"]["protocolVersion"],
                "2025-11-25"
            );
            session_headers(&fixture, 1);
            fixture.finished();
        }
    }
}

/// A real 2024-11-05 handshake followed by list and call on the GET stream.
#[tokio::test]
async fn http_sse_2024_handshake_list_and_call() {
    let mut steps = http_sse();
    steps.extend([
        pushed("tools/list", frame(&listing(1)), false),
        pushed("tools/call", frame(&called(2)), false),
    ]);
    let fixture = Fixture::new(steps).await;
    let connection = connect(quick(&fixture, Some(Generation::Sse)))
        .await
        .unwrap();
    assert_eq!(connection.generation, Generation::Sse);
    exercise(connection).await;
    let requests = fixture.received();
    assert_eq!(requests[0].headers["accept"], "text/event-stream");
    assert_eq!(requests[1].body["params"]["clientInfo"]["name"], "mcpjump");
    for request in &requests[1..] {
        assert_eq!(request.path, "/messages?s=1");
        assert!(!request.headers.contains_key("mcp-session-id"));
    }
    fixture.finished();
    fixture.cleaned_up().await;
}

/// The server withholds the call result until a ping reply has reached its POST endpoint.
#[tokio::test]
async fn http_sse_ping_reply_precedes_the_call_result() {
    let mut steps = http_sse();
    steps.extend([
        pushed(
            "tools/call",
            frame(r#"{"jsonrpc":"2.0","id":90,"method":"ping"}"#),
            false,
        ),
        pushed("response", frame(&called(1)), false),
    ]);
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, Some(Generation::Sse)))
        .await
        .unwrap();
    let called = connection
        .session
        .call_tool("echo", arguments())
        .await
        .unwrap();
    assert_eq!(called.value["content"][0]["text"], "ok");
    connection.session.close().await;
    fixture.finished();
    let requests = fixture.received();
    assert_eq!(
        requests[4].body,
        json!({"jsonrpc":"2.0","id":90,"result":{}})
    );
    fixture.cleaned_up().await;
}

/// A delivered call followed by EOF is never sent twice, in any generation.
#[tokio::test]
async fn every_generation_call_eof_is_delivery_unknown_once() {
    for generation in [
        Generation::Modern,
        Generation::LegacyStreamable,
        Generation::Sse,
    ] {
        let mut steps = match generation {
            Generation::Modern => modern(false),
            Generation::LegacyStreamable => legacy("2025-06-18", false, true),
            Generation::Sse => http_sse(),
        };
        steps.push(if generation == Generation::Sse {
            pushed("tools/call", String::new(), true)
        } else {
            Step::new("tools/call", 200, "text/event-stream", String::new())
        });
        if generation == Generation::LegacyStreamable {
            steps.push(status("DELETE", 200));
        }
        let fixture = Fixture::new(steps).await;
        let mut connection = connect(quick(&fixture, Some(generation))).await.unwrap();
        let failed = connection
            .session
            .call_tool("echo", arguments())
            .await
            .unwrap_err();
        assert_error(&failed, "delivery_unknown");
        connection.session.close().await;
        assert_eq!(
            labels(&fixture)
                .iter()
                .filter(|method| *method == "tools/call")
                .count(),
            1
        );
        fixture.finished();
        fixture.cleaned_up().await;
    }
}

/// Session expiry proves nonexecution and permits exactly one reopen and call retry.
#[tokio::test]
async fn legacy_call_404_reopens_once_and_exhausts_on_second_404() {
    for exhausted in [false, true] {
        let mut steps = legacy("2025-06-18", false, true);
        steps.push(status("tools/call", 404));
        steps.extend([
            reply("initialize", initialize(0, "2025-06-18"), false).session("s2"),
            status("notifications/initialized", 202),
        ]);
        steps.extend([
            status("DELETE", 200),
            if exhausted {
                status("tools/call", 404)
            } else {
                reply("tools/call", called(1), false)
            },
            status("DELETE", 200),
        ]);
        let fixture = Fixture::new(steps).await;
        let mut connection = connect(quick(&fixture, Some(Generation::LegacyStreamable)))
            .await
            .unwrap();
        let outcome = connection.session.call_tool("echo", arguments()).await;
        if exhausted {
            assert_error(&outcome.unwrap_err(), "session_lost");
        } else {
            assert_eq!(outcome.unwrap().value["content"][0]["text"], "ok");
        }
        connection.session.close().await;
        assert_eq!(
            labels(&fixture)
                .iter()
                .filter(|method| *method == "tools/call")
                .count(),
            2
        );
        let requests = fixture.received();
        for (index, session) in [
            (1, "s1"),
            (2, "s1"),
            (4, "s2"),
            (5, "s1"),
            (6, "s2"),
            (7, "s2"),
        ] {
            assert_eq!(requests[index].headers["mcp-session-id"], session);
        }
        assert!(!requests[3].headers.contains_key("mcp-session-id"));
        fixture.finished();
    }
}

/// Both auth statuses keep their kind during list and call on every generation.
#[tokio::test]
async fn auth_rejections_during_list_and_call_are_not_retried() {
    for generation in [
        Generation::Modern,
        Generation::LegacyStreamable,
        Generation::Sse,
    ] {
        for method in ["tools/list", "tools/call"] {
            for denied in [401, 403] {
                let mut steps = match generation {
                    Generation::Modern => modern(false),
                    Generation::LegacyStreamable => legacy("2025-06-18", false, true),
                    Generation::Sse => http_sse(),
                };
                steps.push(status(method, denied));
                if generation == Generation::LegacyStreamable {
                    steps.push(status("DELETE", 200));
                }
                let fixture = Fixture::new(steps).await;
                let mut connection = connect(quick(&fixture, Some(generation))).await.unwrap();
                let failed = if method == "tools/list" {
                    connection.session.list_tools_page(None).await.unwrap_err()
                } else {
                    connection
                        .session
                        .call_tool("echo", arguments())
                        .await
                        .unwrap_err()
                };
                assert_error(&failed, "auth_required");
                assert!(failed.message().contains(&format!("HTTP {denied}")));
                connection.session.close().await;
                fixture.finished();
            }
        }
    }
}

/// Mirrored values use bare ASCII or the specified base64 sentinel for UTF-8.
#[tokio::test]
async fn modern_param_headers_are_encoded_with_method_name_and_version() {
    for (region, encoded) in [("us-west1", "us-west1"), ("é", "=?base64?w6k=?=")] {
        let mut geo = tool("geo");
        geo["inputSchema"] = json!({"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}});
        let mut steps = modern(false);
        steps.extend([
            reply("tools/list", result(1, &json!({"tools":[geo]})), false),
            reply("tools/call", called(2), false),
        ]);
        let fixture = Fixture::new(steps).await;
        let mut connection = connect(quick(&fixture, None)).await.unwrap();
        connection.session.list_tools_page(None).await.unwrap();
        let args = json!({"region":region}).as_object().unwrap().clone();
        connection.session.call_tool("geo", args).await.unwrap();
        connection.session.close().await;
        let call = &fixture.received()[2];
        assert_eq!(call.headers["mcp-param-region"], encoded);
        assert_eq!(call.headers["mcp-method"], "tools/call");
        assert_eq!(call.headers["mcp-name"], "geo");
        assert_eq!(call.headers["mcp-protocol-version"], "2026-07-28");
        assert_eq!(call.body["params"]["arguments"]["region"], region);
        fixture.finished();
    }
}

/// A real paginated scan follows the opaque cursor and concatenates pages in order.
#[tokio::test]
async fn list_follows_cursor_and_concatenates_wire_pages() {
    let mut steps = modern(false);
    steps.extend([
        reply(
            "tools/list",
            result(
                1,
                &json!({"tools":[tool("first")],"nextCursor":"opaque next"}),
            ),
            false,
        ),
        reply(
            "tools/list",
            result(2, &json!({"tools":[tool("second")]})),
            true,
        ),
    ]);
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, None)).await.unwrap();
    let list = scan(connection.session.as_mut(), &Limits::default(), None)
        .await
        .unwrap();
    assert_eq!(
        list.tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    connection.session.close().await;
    let requests = fixture.received();
    assert!(requests[1].body["params"].get("cursor").is_none());
    assert_eq!(requests[2].body["params"]["cursor"], "opaque next");
    fixture.finished();
}

/// Raw tool results preserve unknown fields and explicit nulls.
#[tokio::test]
async fn raw_call_results_preserve_server_objects() {
    let cases = [
        (
            json!({"content":[],"isError":true}),
            json!({"content":[],"isError":true}),
            true,
        ),
        (
            json!({"content":[],"structuredContent":{"count":7}}),
            json!({"content":[],"structuredContent":{"count":7}}),
            false,
        ),
        (
            json!({"content":[],"vendor":{"extra":1},"isError":null,"structuredContent":null,"_meta":null}),
            json!({"content":[],"vendor":{"extra":1},"isError":null,"structuredContent":null,"_meta":null}),
            false,
        ),
    ];
    for sse in [false, true] {
        for (raw, expected, is_error) in &cases {
            let mut steps = modern(false);
            steps.push(reply("tools/call", result(1, raw), sse));
            let fixture = Fixture::new(steps).await;
            let mut connection = connect(quick(&fixture, None)).await.unwrap();
            let called = connection
                .session
                .call_tool("echo", arguments())
                .await
                .unwrap();
            assert_eq!(called.value, *expected);
            assert_eq!(called.is_error, *is_error);
            connection.session.close().await;
            fixture.finished();
        }
    }
}

/// Keepalive comments and duplicate ids do not replace the first matching result.
#[tokio::test]
async fn sse_keepalives_notifications_and_duplicate_ids_keep_first_result() {
    let mut steps = modern(true);
    let bytes = format!(
        ": keepalive\n\n{}{}{}",
        frame(r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#),
        frame(&called(1)),
        frame(&result(1, &json!({"content":[],"isError":true})))
    );
    steps.push(Step::new("tools/call", 200, "text/event-stream", bytes));
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, None)).await.unwrap();
    let called = connection
        .session
        .call_tool("echo", arguments())
        .await
        .unwrap();
    assert_eq!(called.value["content"][0]["text"], "ok");
    assert!(!called.is_error);
    connection.session.close().await;
    fixture.finished();
}

/// Returning a result does not wait for EOF, and close drops open response bodies.
#[tokio::test]
async fn an_sse_result_on_an_open_stream_returns_promptly_and_cleans_up() {
    for generation in [Generation::Modern, Generation::LegacyStreamable] {
        let mut steps = if generation == Generation::Modern {
            modern(true)
        } else {
            legacy("2025-06-18", true, true)
        };
        steps.push(reply("tools/call", called(1), true).deliver(Delivery::Open));
        if generation == Generation::LegacyStreamable {
            steps.push(status("DELETE", 200));
        }
        let fixture = Fixture::new(steps).await;
        let mut connection = connect(quick(&fixture, Some(generation))).await.unwrap();
        let called = tokio::time::timeout(
            Duration::from_millis(500),
            connection.session.call_tool("echo", arguments()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(called.value["content"][0]["text"], "ok");
        connection.session.close().await;
        fixture.cleaned_up().await;
        fixture.finished();
    }
}

/// Later session headers are ignored, and configured credentials also reach DELETE.
#[tokio::test]
async fn initialize_session_is_retained_despite_later_headers() {
    for sse in [false, true] {
        let mut steps = legacy("2025-06-18", sse, true);
        steps.extend([
            reply("tools/list", listing(1), sse).session("changed"),
            reply("tools/call", called(2), sse).session("changed-again"),
            status("DELETE", 200),
        ]);
        let fixture = Fixture::new(steps).await;
        let mut keyed = quick(&fixture, Some(Generation::LegacyStreamable));
        keyed.headers = vec![("X-Key".to_owned(), "dummy-key".to_owned())];
        exercise(connect(keyed).await.unwrap()).await;
        session_headers(&fixture, 1);
        for request in fixture.received() {
            assert_eq!(request.headers["x-key"], "dummy-key");
        }
        fixture.finished();
    }
}

/// Stateless legacy and Modern sessions never echo arbitrary response session headers.
#[tokio::test]
async fn sessionless_legacy_and_modern_do_not_echo_later_session_headers() {
    for generation in [Generation::Modern, Generation::LegacyStreamable] {
        let mut steps = if generation == Generation::Modern {
            vec![reply("server/discover", discover(0), false).session("modern-ignored")]
        } else {
            legacy("2025-06-18", false, false)
        };
        steps.extend([
            reply("tools/list", listing(1), false).session("late"),
            reply("tools/call", called(2), false),
        ]);
        let fixture = Fixture::new(steps).await;
        exercise(connect(quick(&fixture, Some(generation))).await.unwrap()).await;
        for request in fixture.received() {
            assert!(!request.headers.contains_key("mcp-session-id"));
        }
        fixture.finished();
    }
}

/// Best-effort DELETE failures do not replace a successful operation's result.
#[tokio::test]
async fn delete_405_500_and_network_failure_do_not_fail_close() {
    for deleted in [
        status("DELETE", 405),
        status("DELETE", 500),
        status("DELETE", 200).deliver(Delivery::Broken),
    ] {
        let mut steps = legacy("2025-06-18", false, true);
        steps.extend([
            reply("tools/list", listing(1), false),
            reply("tools/call", called(2), false),
            deleted,
        ]);
        let fixture = Fixture::new(steps).await;
        exercise(
            connect(quick(&fixture, Some(Generation::LegacyStreamable)))
                .await
                .unwrap(),
        )
        .await;
        fixture.finished();
        session_headers(&fixture, 1);
    }
}

/// A malicious endpoint is rejected before the other listener receives credentials.
#[tokio::test]
async fn http_sse_disallowed_endpoint_never_receives_credentials() {
    let victim = Fixture::new(Vec::new()).await;
    for endpoint in [
        victim.url.to_string(),
        "http://127.0.0.1/messages#fragment".to_owned(),
        "http://user:pass@127.0.0.1/messages".to_owned(),
        "file:///messages".to_owned(),
    ] {
        let fixture = Fixture::new(vec![
            Step::new(
                "GET",
                200,
                "text/event-stream",
                format!("event: endpoint\ndata: {endpoint}\n\n"),
            )
            .deliver(Delivery::Start),
        ])
        .await;
        let mut keyed = quick(&fixture, Some(Generation::Sse));
        keyed.headers = vec![("Authorization".to_owned(), "Bearer dummy-secret".to_owned())];
        let failed = connect(keyed).await.unwrap_err();
        assert_error(&failed, "url_rejected");
        fixture.finished();
        assert_eq!(
            fixture.received()[0].headers["authorization"],
            "Bearer dummy-secret"
        );
        assert!(victim.received().is_empty());
        fixture.cleaned_up().await;
    }
}

/// A rejected saved generation goes first, then the remaining generations in plan order.
#[tokio::test]
async fn probe_tries_saved_generation_then_remaining_generations_on_wire() {
    for saved in [
        Generation::Modern,
        Generation::LegacyStreamable,
        Generation::Sse,
    ] {
        let steps = match saved {
            Generation::Modern => {
                let mut steps = vec![status("server/discover", 405)];
                steps.extend(legacy("2025-06-18", false, false));
                steps
            }
            Generation::LegacyStreamable => vec![
                status("initialize", 405),
                reply("server/discover", discover(0), false),
            ],
            Generation::Sse => vec![
                status("GET", 405),
                reply("server/discover", discover(0), false),
            ],
        };
        let fixture = Fixture::new(steps).await;
        let connection = connect(quick(&fixture, Some(saved))).await.unwrap();
        assert_eq!(
            connection.generation,
            if saved == Generation::Modern {
                Generation::LegacyStreamable
            } else {
                Generation::Modern
            }
        );
        connection.session.close().await;
        fixture.finished();
    }
}

/// Exhausting two generations still preserves each saved-generation probe order.
#[tokio::test]
async fn probe_exhausts_saved_order_before_the_third_generation() {
    for saved in [
        Generation::Modern,
        Generation::LegacyStreamable,
        Generation::Sse,
    ] {
        let mut steps = match saved {
            Generation::Modern => vec![status("server/discover", 405), status("initialize", 405)],
            Generation::LegacyStreamable => {
                vec![status("initialize", 405), status("server/discover", 405)]
            }
            Generation::Sse => vec![status("GET", 405), status("server/discover", 405)],
        };
        let found = if saved == Generation::Sse {
            steps.extend(legacy("2025-06-18", false, false));
            Generation::LegacyStreamable
        } else {
            steps.extend(http_sse());
            Generation::Sse
        };
        let fixture = Fixture::new(steps).await;
        let connection = connect(quick(&fixture, Some(saved))).await.unwrap();
        assert_eq!(connection.generation, found);
        connection.session.close().await;
        fixture.finished();
        fixture.cleaned_up().await;
    }
}

/// Broken HTTP transfers during calls retain delivery uncertainty and never retry.
#[tokio::test]
async fn streamable_call_network_disconnect_is_delivery_unknown_once() {
    for generation in [Generation::Modern, Generation::LegacyStreamable] {
        let mut steps = if generation == Generation::Modern {
            modern(false)
        } else {
            legacy("2025-06-18", false, true)
        };
        steps.push(
            Step::new("tools/call", 200, "text/event-stream", "data: {".to_owned())
                .deliver(Delivery::Broken),
        );
        if generation == Generation::LegacyStreamable {
            steps.push(status("DELETE", 200));
        }
        let fixture = Fixture::new(steps).await;
        let mut connection = connect(quick(&fixture, Some(generation))).await.unwrap();
        let failed = connection
            .session
            .call_tool("echo", arguments())
            .await
            .unwrap_err();
        assert_error(&failed, "delivery_unknown");
        connection.session.close().await;
        fixture.finished();
    }
}

/// Literal replies retain whitespace, comments, chosen status and content type.
#[tokio::test]
async fn raw_fixture_replays_json_and_sse_bytes_verbatim() {
    use mcpjump::http::body::{SizeLimit, read_body};
    use mcpjump::http::client::Redirects;

    use crate::support::http::client;

    for (media, bytes) in [
        (
            "application/json; charset=utf-8",
            " { \"literal\" : null }\n",
        ),
        (
            "text/event-stream",
            ": keepalive\n\nevent: message\ndata: {\"literal\":null}\n\ndata: {",
        ),
    ] {
        let fixture = Fixture::new(vec![Step::new("echo", 207, media, bytes.to_owned())]).await;
        let url = fixture.url.join("/messages?s=1").unwrap();
        let http = client();
        let request = http
            .request(reqwest::Method::POST, url, Redirects::Never)
            .header("x-key", "dummy-key")
            .header("x-unselected", "discard")
            .json(&json!({"jsonrpc":"2.0","id":4,"method":"echo","params":{"n":1}}));
        let response = http.send(request, after(500)).await.unwrap();
        assert_eq!(response.status().as_u16(), 207);
        assert_eq!(response.headers()["content-type"], media);
        assert_eq!(
            read_body(response, SizeLimit::response(1024), after(500))
                .await
                .unwrap(),
            bytes.as_bytes()
        );
        let requests = fixture.received();
        assert_eq!(requests[0].path, "/messages?s=1");
        assert_eq!(requests[0].body["params"], json!({"n":1}));
        assert_eq!(requests[0].headers["x-key"], "dummy-key");
        assert!(!requests[0].headers.contains_key("x-unselected"));
        fixture.finished();
    }
}

/// The broken-body script closes the socket before DELETE receives response headers.
#[tokio::test]
async fn raw_fixture_delete_disconnect_is_a_network_failure() {
    use mcpjump::http::client::Redirects;

    use crate::support::http::client;

    let fixture = Fixture::new(vec![status("DELETE", 200).deliver(Delivery::Broken)]).await;
    let http = client();
    let request = http.request(
        reqwest::Method::DELETE,
        fixture.url.clone(),
        Redirects::Never,
    );
    let failed = http.send(request, after(500)).await.unwrap_err();
    assert_error(&failed, "network");
    fixture.finished();
}

/// The literal release-smoke rejection must negotiate Legacy and permit tools/list.
#[tokio::test]
async fn deepwiki_exact_http_error_negotiates_legacy_streamable() {
    let body = r#"{"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Bad Request: Unsupported protocol version: 2026-07-28. Supported versions: 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25"}}"#;
    let mut steps = vec![Step::new(
        "server/discover",
        400,
        "application/json",
        body.to_owned(),
    )];
    steps.extend(legacy("2025-03-26", false, false));
    steps.push(reply("tools/list", listing(1), false));
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, None)).await.unwrap();
    assert_eq!(connection.generation, Generation::LegacyStreamable);
    let page = connection.session.list_tools_page(None).await.unwrap();
    assert_eq!(page.tools[0].name, "echo");
    connection.session.close().await;
    let received = fixture.received();
    assert_eq!(received[1].label(), "initialize");
    assert_eq!(received[1].body["params"]["protocolVersion"], "2025-11-25");
    assert_eq!(received[3].headers["mcp-protocol-version"], "2025-03-26");
    assert!(!received[0].headers.contains_key("mcp-session-id"));
    fixture.finished();
}

/// HTML pages and error bodies beyond the 64 KiB cap retain their legacy signal.
#[tokio::test]
async fn discover_404_html_and_oversized_errors_fall_back_to_legacy() {
    let error = error(99, -32020, &Value::Null);
    let oversized = format!("{error}{}", " ".repeat(64 * 1024 + 1 - error.len()));
    for (media, body) in [
        ("text/html", "<html>Not Found</html>".to_owned()),
        ("application/json", oversized),
    ] {
        let mut steps = vec![Step::new("server/discover", 404, media, body)];
        steps.extend(legacy("2025-06-18", false, false));
        let fixture = Fixture::new(steps).await;
        let connection = connect(quick(&fixture, None)).await.unwrap();
        assert_eq!(connection.generation, Generation::LegacyStreamable);
        assert_eq!(fixture.received()[1].label(), "initialize");
        connection.session.close().await;
        fixture.finished();
    }
}

/// Recovery exposes a session-less initialize rejection without probe error replacement.
#[tokio::test]
async fn sessionless_initialize_http_rejections_ignore_error_ids_and_empty_bodies() {
    for code in [400, 404, 405] {
        for body in [error(99, -32600, &Value::Null), String::new()] {
            let mut steps = legacy("2025-06-18", false, true);
            steps.extend([
                status("tools/list", 404),
                Step::new("initialize", code, "application/json", body),
                status("DELETE", 200),
            ]);
            let fixture = Fixture::new(steps).await;
            let mut connection = connect(quick(&fixture, Some(Generation::LegacyStreamable)))
                .await
                .unwrap();
            let failed = connection.session.list_tools_page(None).await.unwrap_err();
            assert_error(&failed, "unsupported_server");
            let status = axum::http::StatusCode::from_u16(code).unwrap();
            assert_eq!(
                failed.message(),
                format!(
                    "{} rejected initialize with HTTP {status}",
                    fixture.url.origin().ascii_serialization()
                )
            );
            connection.session.close().await;
            assert!(!fixture.received()[3].headers.contains_key("mcp-session-id"));
            fixture.finished();
        }
    }
}

/// A saved Legacy connection without a session still correlates non-handshake errors.
#[tokio::test]
async fn sessionless_tools_list_http_error_keeps_the_id_check() {
    let mut steps = legacy("2025-06-18", false, false);
    steps.push(Step::new(
        "tools/list",
        400,
        "application/json",
        error(99, -32600, &Value::Null),
    ));
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, Some(Generation::LegacyStreamable)))
        .await
        .unwrap();
    let failed = connection.session.list_tools_page(None).await.unwrap_err();
    assert_error(&failed, "protocol_error");
    assert!(!fixture.received()[2].headers.contains_key("mcp-session-id"));
    connection.session.close().await;
    fixture.finished();
}

/// Re-tagging preserves Modern's fatal header and capability rejection codes.
#[tokio::test]
async fn legacy_http_discover_signal_preserves_modern_rejection_classification() {
    for status in [400, 404, 405] {
        for code in [-32020, -32021] {
            let fixture = Fixture::new(vec![Step::new(
                "server/discover",
                status,
                "application/json",
                error(99, code, &Value::Null),
            )])
            .await;
            let failed = connect(quick(&fixture, None)).await.unwrap_err();
            assert_error(&failed, "server_error");
            assert!(failed.message().contains(&code.to_string()));
            fixture.finished();
        }
    }
}
