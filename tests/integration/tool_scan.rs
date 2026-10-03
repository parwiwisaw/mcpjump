//! Bounded tool discovery against a scripted session.

use mcpjump::config::limits::Limits;
use mcpjump::error::ErrorKind;
use mcpjump::mcp::tools::{MAX_TOOL_NAME_LEN, ToolList, scan, valid_name};
use serde_json::json;

use crate::support::fakes::connector::{FakeSession, tool};

fn named(names: &[&str]) -> Vec<serde_json::Value> {
    names.iter().map(|name| tool(name, &json!({}))).collect()
}

fn names(list: &ToolList) -> Vec<&str> {
    list.tools.iter().map(|tool| tool.name.as_str()).collect()
}

async fn limit_message(mut session: FakeSession, limits: &Limits) -> String {
    let error = scan(&mut session, limits, None).await.unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ToolListLimit);
    error.message().to_owned()
}

#[test]
fn tool_names_follow_the_naming_rule() {
    assert!(valid_name("a-Z_0.9"));
    assert!(valid_name(&"a".repeat(MAX_TOOL_NAME_LEN)));
    for bad in ["", "a b", "a/b", "é", &"a".repeat(MAX_TOOL_NAME_LEN + 1)] {
        assert!(!valid_name(bad), "{bad:?}");
    }
}

#[tokio::test]
async fn a_scan_follows_cursors_and_skips_invalid_names() {
    let mut session = FakeSession::default()
        .page(&named(&["a", "bad name"]), Some("c1"))
        .page(&named(&["b"]), None);
    let list = scan(&mut session, &Limits::default(), None).await.unwrap();
    assert_eq!((names(&list), list.skipped), (vec!["a", "b"], 1));
}

#[tokio::test]
async fn a_wanted_tool_stops_the_scan_at_its_page() {
    let mut session = FakeSession::default()
        .page(&named(&["a", "bad name"]), Some("c1"))
        .page(&named(&["b", "c"]), Some("c2"));
    let log = session.log();
    let list = scan(&mut session, &Limits::default(), Some("b"))
        .await
        .unwrap();
    assert_eq!((names(&list), list.skipped), (vec!["b"], 1));
    assert_eq!(*log.lock().unwrap(), ["list ", "list c1"]);
    let mut session = FakeSession::default().page(&named(&["a"]), None);
    let missing = scan(&mut session, &Limits::default(), Some("z"))
        .await
        .unwrap();
    assert_eq!(missing, ToolList::default());
}

#[tokio::test]
async fn page_count_tool_count_and_bytes_are_capped() {
    let limits = Limits {
        max_tool_pages: 2,
        ..Limits::default()
    };
    let pages = FakeSession::default()
        .page(&[], Some("c1"))
        .page(&[], Some("c2"));
    assert!(
        limit_message(pages, &limits)
            .await
            .contains("max_tool_pages (2)")
    );
    let many: Vec<String> = (0..=1000).map(|n| format!("t{n}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let tools = FakeSession::default().page(&named(&many), None);
    assert!(
        limit_message(tools, &Limits::default())
            .await
            .contains("max_tools (1000)")
    );
    let limits = Limits {
        max_tools_bytes: 1024,
        ..Limits::default()
    };
    let big = json!({"name": "a", "description": "x".repeat(1024)});
    let bytes = FakeSession::default().page(&[big], None);
    assert!(
        limit_message(bytes, &limits)
            .await
            .contains("max_tools_bytes (1024)")
    );
}

#[tokio::test]
async fn a_repeated_cursor_ends_the_scan() {
    let session = FakeSession::default()
        .page(&[], Some("same"))
        .page(&[], Some("same"));
    let message = limit_message(session, &Limits::default()).await;
    assert_eq!(message, "the server repeated a tools/list cursor");
}
