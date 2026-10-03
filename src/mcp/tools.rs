//! Bounded tool discovery: pages, tool count and bytes are capped, a
//! repeated cursor ends the scan, and tools with invalid names are skipped.

use std::collections::HashSet;

use crate::config::limits::Limits;
use crate::error::{Error, ErrorKind};
use crate::mcp::session::{McpSession, Tool};

/// Longest tool name.
pub const MAX_TOOL_NAME_LEN: usize = 128;

/// The tools a scan kept.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ToolList {
    /// Tools with valid names, in server order. With a wanted name, at most
    /// that one tool.
    pub tools: Vec<Tool>,
    /// How many tools were skipped for an invalid name.
    pub skipped: u64,
}

/// Whether `name` follows the tool naming rule: 1 to 128 characters from
/// `A-Z a-z 0-9 _ . -`.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    (1..=MAX_TOOL_NAME_LEN).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

/// Lists the server's tools. With `wanted`, stops at the page that holds
/// it and keeps only that tool; `tools` is empty if no page does.
///
/// # Errors
/// `tool_list_limit` when the listing passes `max_tool_pages`, `max_tools`
/// or `max_tools_bytes`, or repeats a cursor; the session's errors.
pub async fn scan(
    session: &mut dyn McpSession,
    limits: &Limits,
    wanted: Option<&str>,
) -> Result<ToolList, Error> {
    let mut tally = Tally::default();
    let mut seen = HashSet::new();
    let mut list = ToolList::default();
    let mut cursor = None;
    for _ in 0..limits.max_tool_pages {
        let page = session.list_tools_page(cursor).await?;
        for tool in page.tools {
            tally.add(&tool, limits)?;
            if !valid_name(&tool.name) {
                list.skipped += 1;
            } else if wanted.is_none_or(|name| name == tool.name) {
                list.tools.push(tool);
            }
        }
        if wanted.is_some() && !list.tools.is_empty() {
            return Ok(list);
        }
        let Some(next) = page.next_cursor else {
            return Ok(list);
        };
        if !seen.insert(next.clone()) {
            return Err(limit("repeated a tools/list cursor"));
        }
        cursor = Some(next);
    }
    Err(limit(&format!(
        "listed more than max_tool_pages ({}) pages of tools",
        limits.max_tool_pages
    )))
}

/// Counts every tool received, valid or not.
#[derive(Debug, Default)]
struct Tally {
    tools: u64,
    bytes: u64,
}

impl Tally {
    fn add(&mut self, tool: &Tool, limits: &Limits) -> Result<(), Error> {
        self.tools += 1;
        let size = u64::try_from(tool.definition.to_string().len()).unwrap_or(u64::MAX);
        self.bytes = self.bytes.saturating_add(size);
        if self.tools > limits.max_tools {
            return Err(limit(&format!(
                "listed more than max_tools ({})",
                limits.max_tools
            )));
        }
        if self.bytes > limits.max_tools_bytes {
            return Err(limit(&format!(
                "listed more than max_tools_bytes ({}) of tool definitions",
                limits.max_tools_bytes
            )));
        }
        Ok(())
    }
}

fn limit(what: &str) -> Error {
    Error::new(ErrorKind::ToolListLimit, format!("the server {what}"))
}
