//! In-house client boundaries and cleanup over local wire fixtures.

use mcpjump::config::model::Generation;
use serde_json::{Value, json};

use crate::mcp_wire::{
    discover, error, frame, labels, legacy, listing, modern, quick, reply, result,
};
use crate::support::http::after;
use crate::support::mcp_client::{arguments, connect};
use crate::support::raw_mcp_server::{Delivery, Fixture, Step};

/// SSE arrays are an explicit protocol error, with no probe fallback.
#[tokio::test]
async fn sse_batches_are_rejected_without_fallback() {
    let batch = format!("[{}]", discover(0));
    let fixture = Fixture::new(vec![reply("server/discover", batch, true)]).await;
    let error = connect(quick(&fixture, None)).await.unwrap_err();
    assert_eq!(error.kind().as_str(), "protocol_error");
    assert!(error.message().contains("batches are not supported"));
    fixture.finished();
}

/// Typed handshake results and correlated Legacy errors never cause a downgrade.
#[tokio::test]
async fn malformed_handshake_results_and_legacy_rpc_errors_end_the_probe() {
    for (generation, method) in [
        (Generation::Modern, "server/discover"),
        (Generation::LegacyStreamable, "initialize"),
    ] {
        for sse in [false, true] {
            let fixture = Fixture::new(vec![reply(method, result(0, &json!({})), sse)]).await;
            let error = connect(quick(&fixture, Some(generation)))
                .await
                .unwrap_err();
            assert_eq!(error.kind().as_str(), "protocol_error");
            fixture.finished();
        }
    }
    let fixture = Fixture::new(vec![reply(
        "initialize",
        error(0, -32601, &Value::Null),
        true,
    )])
    .await;
    let error = connect(quick(&fixture, Some(Generation::LegacyStreamable)))
        .await
        .unwrap_err();
    assert_eq!(error.kind().as_str(), "server_error");
    assert!(error.message().ends_with("JSON-RPC error -32601"));
    fixture.finished();
}

/// Discover results with no shared version and malformed negotiation data fall back once.
#[tokio::test]
async fn incompatible_modern_versions_advance_to_legacy() {
    let no_shared = discover(0).replace("2026-07-28", "1999-01-01");
    let rejections = [
        Value::Null,
        json!({}),
        json!({"supported":null}),
        json!({"supported":[7]}),
        json!({"supported":["1999-01-01"]}),
    ];
    let bodies =
        std::iter::once(no_shared).chain(rejections.iter().map(|data| error(0, -32022, data)));
    for body in bodies {
        let mut steps = vec![reply("server/discover", body, true)];
        steps.extend(legacy("2025-11-25", false, false));
        let fixture = Fixture::new(steps).await;
        let connection = connect(quick(&fixture, None)).await.unwrap();
        assert_eq!(connection.generation, Generation::LegacyStreamable);
        connection.session.close().await;
        fixture.finished();
    }
}

/// A malformed list and unsupported call extensions are kept as explicit errors.
#[tokio::test]
async fn wrong_list_and_call_result_shapes_are_rejected() {
    for (method, value, expected) in [
        ("tools/list", json!({}), "protocol_error"),
        ("tools/call", json!({}), "protocol_error"),
        ("tools/call", json!({"task":{}}), "unsupported_feature"),
        (
            "tools/call",
            json!({"resultType":"input_required","requestState":"opaque"}),
            "unsupported_feature",
        ),
    ] {
        let mut steps = modern(false);
        steps.push(reply(method, result(1, &value), true));
        let fixture = Fixture::new(steps).await;
        let mut connection = connect(quick(&fixture, None)).await.unwrap();
        let error = if method == "tools/list" {
            connection.session.list_tools_page(None).await.unwrap_err()
        } else {
            connection
                .session
                .call_tool("echo", arguments())
                .await
                .unwrap_err()
        };
        assert_eq!(error.kind().as_str(), expected);
        connection.session.close().await;
        fixture.finished();
    }
}

/// Standard header metadata retention has the same count and byte bounds as discovery.
#[tokio::test]
async fn modern_header_metadata_is_bounded_and_invalid_tools_are_dropped() {
    for count_bound in [false, true] {
        let mut steps = modern(false);
        let tools = json!({"tools":[{"name":"a","inputSchema":{}},{"name":"b","inputSchema":{}}]});
        steps.push(reply("tools/list", result(1, &tools), false));
        let fixture = Fixture::new(steps).await;
        let mut target = quick(&fixture, None);
        if count_bound {
            target.limits.max_tools = 1;
        } else {
            target.limits.max_tools_bytes = 1;
        }
        let mut connection = connect(target).await.unwrap();
        let error = connection.session.list_tools_page(None).await.unwrap_err();
        assert_eq!(error.kind().as_str(), "tool_list_limit");
        connection.session.close().await;
        fixture.finished();
    }
    let mut steps = modern(false);
    let tools = json!({"tools":[{"name":"bad","inputSchema":{"properties":{"p":{"type":"string","x-mcp-header":""}}}},{"name":"good","inputSchema":{}}]});
    steps.push(reply("tools/list", result(1, &tools), false));
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, None)).await.unwrap();
    let page = connection.session.list_tools_page(None).await.unwrap();
    assert_eq!(page.tools.len(), 1);
    assert_eq!(page.tools[0].name, "good");
    connection.session.close().await;
    fixture.finished();
}

/// A missing reply outlives `request_timeout` only for tools/call, then drops its stream.
#[tokio::test]
async fn reply_deadlines_drop_streams_without_cancellation_posts() {
    for call in [false, true] {
        let mut steps = modern(false);
        let method = if call { "tools/call" } else { "tools/list" };
        steps.push(
            Step::new(
                method,
                200,
                "text/event-stream",
                ": keepalive\n\n".to_owned(),
            )
            .deliver(Delivery::Open),
        );
        let fixture = Fixture::new(steps).await;
        let mut target = quick(&fixture, None);
        target.limits.stream_idle_secs = 10;
        target.deadline = after(if call { 200 } else { 2_000 });
        let mut connection = connect(target).await.unwrap();
        let error = if call {
            connection
                .session
                .call_tool("echo", arguments())
                .await
                .unwrap_err()
        } else {
            connection.session.list_tools_page(None).await.unwrap_err()
        };
        if call {
            assert_eq!(error.kind().as_str(), "delivery_unknown");
        } else {
            assert!(["request_timeout", "stream_timeout"].contains(&error.kind().as_str()));
        }
        connection.session.close().await;
        assert_eq!(labels(&fixture), ["server/discover", method]);
        fixture.cleaned_up().await;
        fixture.finished();
    }
}

/// Modern violations are protocol errors even during calls; they generate no response POST.
#[tokio::test]
async fn modern_call_server_requests_fail_without_reply_posts() {
    let mut steps = modern(false);
    steps.push(Step::new(
        "tools/call",
        200,
        "text/event-stream",
        frame(r#"{"jsonrpc":"2.0","id":90,"method":"ping"}"#),
    ));
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, None)).await.unwrap();
    let error = connection
        .session
        .call_tool("echo", arguments())
        .await
        .unwrap_err();
    assert_eq!(error.kind().as_str(), "protocol_error");
    connection.session.close().await;
    assert_eq!(labels(&fixture), ["server/discover", "tools/call"]);
    fixture.finished();
}

/// Duplicate names update their annotations without exhausting the unique-name bound.
#[tokio::test]
async fn repeated_tool_metadata_updates_within_the_bounds() {
    let mut steps = modern(false);
    steps.extend([
        reply("tools/list", listing(1), false),
        reply("tools/list", listing(2), false),
    ]);
    let fixture = Fixture::new(steps).await;
    let mut target = quick(&fixture, None);
    target.limits.max_tools = 1;
    let mut connection = connect(target).await.unwrap();
    for _ in 0..2 {
        connection.session.list_tools_page(None).await.unwrap();
    }
    connection.session.close().await;
    fixture.finished();
}

/// Only handshake rejection statuses permit fallback despite an unrelated error id.
#[tokio::test]
async fn uncorrelated_discover_errors_fall_back_only_on_legacy_http_statuses() {
    for code in [400, 404, 405] {
        let mut steps = vec![Step::new(
            "server/discover",
            code,
            "application/json",
            error(99, -32601, &Value::Null),
        )];
        steps.extend(legacy("2025-06-18", false, false));
        let fixture = Fixture::new(steps).await;
        let connection = connect(quick(&fixture, None)).await.unwrap();
        assert_eq!(connection.generation, Generation::LegacyStreamable);
        assert_eq!(fixture.received()[1].label(), "initialize");
        connection.session.close().await;
        fixture.finished();
    }
    let fixture = Fixture::new(vec![Step::new(
        "server/discover",
        500,
        "application/json",
        error(99, -32601, &Value::Null),
    )])
    .await;
    let failed = connect(quick(&fixture, None)).await.unwrap_err();
    assert_eq!(failed.kind().as_str(), "protocol_error");
    fixture.finished();
}

/// Explicit acceptance without a reply is a protocol failure, not fallback.
#[tokio::test]
async fn accepted_requests_without_replies_are_protocol_errors() {
    let fixture = Fixture::new(vec![crate::mcp_wire::status("server/discover", 202)]).await;
    let error = connect(quick(&fixture, None)).await.unwrap_err();
    assert_eq!(error.kind().as_str(), "protocol_error");
    fixture.finished();
}

/// Data-less message events are skipped; incomplete HTTP+SSE replies drop the GET.
#[tokio::test]
async fn empty_events_are_skipped_and_failed_persistent_streams_end() {
    let mut steps = modern(false);
    steps.push(Step::new(
        "tools/list",
        200,
        "text/event-stream",
        format!("event: message\n\n{}", frame(&listing(1))),
    ));
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, None)).await.unwrap();
    connection.session.list_tools_page(None).await.unwrap();
    connection.session.close().await;
    fixture.finished();
    let mut steps = crate::mcp_wire::http_sse();
    steps.extend([
        Step::new(
            "tools/list",
            202,
            "application/json",
            "data: {\n\n".to_owned(),
        )
        .deliver(Delivery::Push(true)),
        crate::mcp_wire::status("tools/list", 202),
    ]);
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, Some(Generation::Sse)))
        .await
        .unwrap();
    for _ in 0..2 {
        let error = connection.session.list_tools_page(None).await.unwrap_err();
        assert_eq!(error.kind().as_str(), "protocol_error");
    }
    connection.session.close().await;
    fixture.cleaned_up().await;
    fixture.finished();
}

/// HTTP error bodies that contain another result remain status failures.
#[tokio::test]
async fn non_error_rpc_bodies_do_not_hide_http_status_failures() {
    let fixture = Fixture::new(vec![Step::new(
        "server/discover",
        500,
        "application/json",
        discover(0),
    )])
    .await;
    let error = connect(quick(&fixture, None)).await.unwrap_err();
    assert_eq!(error.kind().as_str(), "http_status");
    fixture.finished();
}

/// Malformed JSON and envelopes exercise both reply readers without reflecting input.
#[tokio::test]
async fn malformed_wire_replies_fail_in_json_and_sse() {
    for sse in [false, true] {
        for body in [
            "{",
            r#"{"jsonrpc":"2.0","id":1,"result":[],"secret":"token"}"#,
        ] {
            let mut steps = modern(false);
            steps.push(reply("tools/list", body.to_owned(), sse));
            let fixture = Fixture::new(steps).await;
            let mut connection = connect(quick(&fixture, None)).await.unwrap();
            let error = connection.session.list_tools_page(None).await.unwrap_err();
            assert_eq!(error.kind().as_str(), "protocol_error");
            assert!(!error.message().contains("token"));
            connection.session.close().await;
            fixture.finished();
        }
    }
    let body = r#"{"jsonrpc":"2.0","id":0,"error":{"code":"secret"}}"#;
    let fixture = Fixture::new(vec![Step::new(
        "server/discover",
        400,
        "application/json",
        body.to_owned(),
    )])
    .await;
    let error = connect(quick(&fixture, None)).await.unwrap_err();
    assert_eq!(error.kind().as_str(), "protocol_error");
    fixture.finished();
}

/// Rejection of a server-request reply stops Legacy Streamable and HTTP+SSE.
#[tokio::test]
async fn rejected_legacy_server_request_replies_stop_the_operation() {
    let mut steps = legacy("2025-06-18", false, false);
    steps.extend([
        reply(
            "tools/list",
            r#"{"jsonrpc":"2.0","id":90,"method":"ping"}"#.to_owned(),
            true,
        ),
        crate::mcp_wire::status("response", 500),
    ]);
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, Some(Generation::LegacyStreamable)))
        .await
        .unwrap();
    let error = connection.session.list_tools_page(None).await.unwrap_err();
    assert_eq!(error.kind().as_str(), "http_status");
    connection.session.close().await;
    fixture.finished();
    let mut steps = crate::mcp_wire::http_sse();
    steps.push(
        Step::new("tools/list", 202, "application/json", String::new()).deliver(Delivery::Broken),
    );
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, Some(Generation::Sse)))
        .await
        .unwrap();
    let error = connection.session.list_tools_page(None).await.unwrap_err();
    assert_eq!(error.kind().as_str(), "network");
    connection.session.close().await;
    fixture.cleaned_up().await;
    fixture.finished();
}

/// Failure of a permitted retry or initialized notification ends negotiation immediately.
#[tokio::test]
async fn negotiation_followup_failures_are_not_retried() {
    let cases = [
        vec![
            reply(
                "server/discover",
                error(0, -32022, &json!({"supported":["2026-07-28"]})),
                false,
            ),
            crate::mcp_wire::status("server/discover", 401),
        ],
        vec![
            legacy("2025-06-18", false, false).remove(0),
            crate::mcp_wire::status("notifications/initialized", 401),
        ],
    ];
    for (index, steps) in cases.into_iter().enumerate() {
        let fixture = Fixture::new(steps).await;
        let generation = if index == 0 {
            Generation::Modern
        } else {
            Generation::LegacyStreamable
        };
        let error = connect(quick(&fixture, Some(generation)))
            .await
            .unwrap_err();
        assert_eq!(error.kind().as_str(), "auth_required");
        fixture.finished();
    }
}

/// Unknown fields never override valid raw tool output; only boolean true signals failure.
#[tokio::test]
async fn raw_results_preserve_unknown_fields_and_read_only_boolean_true() {
    for flag in [
        json!(false),
        json!(true),
        json!(null),
        json!("true"),
        json!(1),
    ] {
        let value = json!({"content":[],"isError":flag,"task":{"vendor":true},"resultType":"vendor","_meta":null});
        let mut steps = modern(false);
        steps.push(reply("tools/call", result(1, &value), false));
        let fixture = Fixture::new(steps).await;
        let mut connection = connect(quick(&fixture, None)).await.unwrap();
        let result = connection
            .session
            .call_tool("echo", arguments())
            .await
            .unwrap();
        assert_eq!(result.value, value);
        assert_eq!(result.is_error, flag == true);
        connection.session.close().await;
        fixture.finished();
    }
}

/// A subsequent expired request cannot spend the single recovery allowance again.
#[tokio::test]
async fn recovered_sessions_are_not_reopened_on_later_requests() {
    let mut steps = legacy("2025-06-18", false, true);
    steps.push(crate::mcp_wire::status("tools/list", 404));
    let mut recovered = legacy("2025-06-18", false, true);
    recovered[0] = reply(
        "initialize",
        crate::mcp_wire::initialize(0, "2025-06-18"),
        false,
    )
    .session("s2");
    steps.extend(recovered);
    steps.extend([
        crate::mcp_wire::status("DELETE", 200),
        reply("tools/list", listing(1), false),
        crate::mcp_wire::status("tools/list", 404),
        crate::mcp_wire::status("DELETE", 200),
    ]);
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, Some(Generation::LegacyStreamable)))
        .await
        .unwrap();
    connection.session.list_tools_page(None).await.unwrap();
    let error = connection.session.list_tools_page(None).await.unwrap_err();
    assert_eq!(error.kind().as_str(), "session_lost");
    connection.session.close().await;
    for request in fixture
        .received()
        .iter()
        .filter(|request| request.label() == "DELETE")
    {
        assert_eq!(request.headers["mcp-protocol-version"], "2025-06-18");
    }
    fixture.finished();
}

/// Successful notification and response POSTs accept 200 without reading a reply.
#[tokio::test]
async fn legacy_notification_and_response_posts_accept_empty_200_bodies() {
    let mut steps = legacy("2025-06-18", false, false);
    steps[1] = crate::mcp_wire::status("notifications/initialized", 200);
    steps.extend([
        Step::new(
            "tools/list",
            200,
            "text/event-stream",
            format!(
                "{}{}",
                frame(r#"{"jsonrpc":"2.0","id":90,"method":"ping"}"#),
                frame(&listing(1))
            ),
        ),
        crate::mcp_wire::status("response", 200),
    ]);
    let fixture = Fixture::new(steps).await;
    let mut connection = connect(quick(&fixture, Some(Generation::LegacyStreamable)))
        .await
        .unwrap();
    connection.session.list_tools_page(None).await.unwrap();
    connection.session.close().await;
    fixture.finished();
}

#[tokio::test]
async fn pre_push_mcp_red_filtered_definitions_still_obey_received_count() {
    let tools: Vec<Value> = (0..1001)
        .map(|_| json!({"name":"","inputSchema":{"properties":{"":{"x-mcp-header":0}}}}))
        .collect();
    let mut steps = modern(false);
    steps.push(reply(
        "tools/list",
        result(1, &json!({"tools":tools})),
        false,
    ));
    let fixture = Fixture::new(steps).await;
    let target = quick(&fixture, None);
    let limits = target.limits.clone();
    let mut connection = connect(target).await.unwrap();
    let outcome = mcpjump::mcp::tools::scan(&mut *connection.session, &limits, None).await;
    connection.session.close().await;
    assert_eq!(outcome.unwrap_err().kind().as_str(), "tool_list_limit");
    assert_eq!(labels(&fixture), ["server/discover", "tools/list"]);
    fixture.finished();
}

#[tokio::test]
async fn invalid_models_inside_a_tools_array_are_redacted_protocol_errors() {
    for tools in [
        json!([{"inputSchema": {}}]),
        json!([{"name": "SECRET", "inputSchema": 1}]),
    ] {
        let mut steps = modern(false);
        steps.push(reply(
            "tools/list",
            result(1, &json!({"tools": tools})),
            false,
        ));
        let fixture = Fixture::new(steps).await;
        let mut connection = connect(quick(&fixture, None)).await.unwrap();
        let error = connection.session.list_tools_page(None).await.unwrap_err();
        assert_eq!(error.kind().as_str(), "protocol_error");
        assert!(!error.message().contains("SECRET"));
        connection.session.close().await;
        assert_eq!(labels(&fixture), ["server/discover", "tools/list"]);
        fixture.finished();
    }
}
