//! Received-definition limits apply before annotation and name filtering.

use mcpjump::config::limits::Limits;
use mcpjump::error::{Error, ErrorKind};
use mcpjump::mcp::tools::{ToolList, scan};
use serde_json::{Value, json};

use crate::mcp_wire::{labels, modern, quick, reply, result};
use crate::support::mcp_client::connect;
use crate::support::raw_mcp_server::Fixture;

fn definition(index: usize, filtered: bool, invalid_name: bool) -> Value {
    let name = if invalid_name {
        format!("bad name {index}")
    } else {
        format!("t{index}")
    };
    let schema = if filtered {
        json!({"properties":{"p":{"type":"string","x-mcp-header":""}}})
    } else {
        json!({})
    };
    json!({"name":name,"inputSchema":schema})
}

fn padded(mut definition: Value, size: usize) -> Value {
    definition["description"] = json!("");
    let base = definition.to_string().len();
    definition["description"] = json!("x".repeat(size.checked_sub(base).unwrap()));
    assert_eq!(definition.to_string().len(), size);
    definition
}

async fn received_scan(
    pages: Vec<(Vec<Value>, Option<&str>)>,
    limits: Limits,
    wanted: Option<&str>,
) -> Result<ToolList, Error> {
    let mut steps = modern(false);
    for (index, (tools, cursor)) in pages.into_iter().enumerate() {
        let mut listing = json!({"tools":tools});
        if let Some(cursor) = cursor {
            listing["nextCursor"] = json!(cursor);
        }
        steps.push(reply(
            "tools/list",
            result(u64::try_from(index + 1).unwrap(), &listing),
            false,
        ));
    }
    let expected_lists = steps.len() - 1;
    let fixture = Fixture::new(steps).await;
    let mut target = quick(&fixture, None);
    target.limits = limits.clone();
    let mut connection = connect(target).await.unwrap();
    let outcome = scan(&mut *connection.session, &limits, wanted).await;
    connection.session.close().await;
    assert_eq!(
        labels(&fixture)
            .iter()
            .filter(|label| label.as_str() == "tools/list")
            .count(),
        expected_lists
    );
    fixture.finished();
    outcome
}

#[tokio::test]
async fn received_count_covers_valid_filtered_mixed_and_invalid_names() {
    for kind in 0..3 {
        for invalid_name in [false, true] {
            for count in [3, 4] {
                let definitions = (0..count)
                    .map(|index| {
                        definition(
                            index,
                            kind == 1 || (kind == 2 && index % 2 == 0),
                            invalid_name,
                        )
                    })
                    .collect();
                let limits = Limits {
                    max_tools: 3,
                    ..Limits::default()
                };
                let outcome = received_scan(vec![(definitions, None)], limits, None).await;
                if count == 4 {
                    assert_eq!(outcome.unwrap_err().kind(), ErrorKind::ToolListLimit);
                } else {
                    let list = outcome.unwrap();
                    let valid_names = match kind {
                        0 => vec!["t0", "t1", "t2"],
                        1 => vec![],
                        _ => vec!["t1"],
                    };
                    let expected_skipped = if invalid_name {
                        u64::try_from(valid_names.len()).unwrap()
                    } else {
                        0
                    };
                    let expected_names = if invalid_name { vec![] } else { valid_names };
                    let names: Vec<&str> =
                        list.tools.iter().map(|tool| tool.name.as_str()).collect();
                    assert_eq!(names, expected_names);
                    assert_eq!(list.skipped, expected_skipped);
                }
            }
        }
    }
}

#[tokio::test]
async fn received_bytes_count_filtered_unknown_and_null_fields_at_the_exact_boundary() {
    for filtered in [false, true] {
        for unknown in [false, true] {
            for size in [1024, 1025] {
                let mut raw = definition(0, filtered, false);
                if unknown {
                    raw["vendor"] = Value::Null;
                    raw["ignored"] = json!("retained in raw bytes");
                }
                let raw = padded(raw, size);
                let limits = Limits {
                    max_tools_bytes: 1024,
                    ..Limits::default()
                };
                let outcome = received_scan(vec![(vec![raw], None)], limits, None).await;
                if size == 1025 {
                    assert_eq!(outcome.unwrap_err().kind(), ErrorKind::ToolListLimit);
                } else {
                    assert_eq!(outcome.unwrap().tools.len(), usize::from(!filtered));
                }
            }
        }
    }
}

#[tokio::test]
async fn received_count_accumulates_filtered_pages_without_a_third_rpc() {
    let pages = vec![
        (
            vec![definition(0, true, false), definition(1, true, false)],
            Some("next"),
        ),
        (
            vec![definition(2, true, false), definition(3, true, false)],
            Some("third"),
        ),
    ];
    let limits = Limits {
        max_tools: 3,
        ..Limits::default()
    };
    assert_eq!(
        received_scan(pages, limits, None).await.unwrap_err().kind(),
        ErrorKind::ToolListLimit
    );
}

#[tokio::test]
async fn received_bytes_accumulate_across_pages_at_the_exact_boundary() {
    for size in [512, 513] {
        let pages = vec![
            (vec![padded(definition(0, true, false), 512)], Some("next")),
            (vec![padded(definition(1, true, false), size)], None),
        ];
        let limits = Limits {
            max_tools_bytes: 1024,
            ..Limits::default()
        };
        let outcome = received_scan(pages, limits, None).await;
        if size == 512 {
            assert_eq!(
                outcome.unwrap().tools,
                Vec::<mcpjump::mcp::session::Tool>::new()
            );
        } else {
            assert_eq!(outcome.unwrap_err().kind(), ErrorKind::ToolListLimit);
        }
    }
}

#[tokio::test]
async fn a_terminal_page_at_the_page_limit_succeeds_but_another_cursor_fails() {
    for cursor in [None, Some("third")] {
        let pages = vec![(vec![], Some("second")), (vec![], cursor)];
        let limits = Limits {
            max_tool_pages: 2,
            ..Limits::default()
        };
        let outcome = received_scan(pages, limits, None).await;
        if cursor.is_none() {
            assert_eq!(
                outcome.unwrap().tools,
                Vec::<mcpjump::mcp::session::Tool>::new()
            );
        } else {
            assert_eq!(outcome.unwrap_err().kind(), ErrorKind::ToolListLimit);
        }
    }
}

#[tokio::test]
async fn wanted_tools_end_in_bounds_traversals_and_reject_oversized_pages_first() {
    for count in [3, 4] {
        let definitions = (0..count)
            .map(|index| definition(index, index != 0, false))
            .collect();
        let limits = Limits {
            max_tools: 3,
            ..Limits::default()
        };
        let outcome = received_scan(vec![(definitions, Some("unused"))], limits, Some("t0")).await;
        if count == 3 {
            assert_eq!(outcome.unwrap().tools[0].name, "t0");
        } else {
            assert_eq!(outcome.unwrap_err().kind(), ErrorKind::ToolListLimit);
        }
    }
}
