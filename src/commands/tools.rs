//! `mcpjump tools`.

use std::time::Duration;

use serde_json::{Map, Value};
use tokio::time::Instant;

use crate::app::Deps;
use crate::auth::refresh::{Authorizer, authorized};
use crate::cli::ToolsArgs;
use crate::commands::connect::connect;
use crate::commands::{Context, Reply};
use crate::config::limits::Limits;
use crate::config::model::ServerEntry;
use crate::config::validate::ServerName;
use crate::error::{Error, ErrorKind};
use crate::mcp::session::{McpSession, Tool};
use crate::mcp::tools::scan;
use crate::sys::deadline;

/// Protocol attempts one command may make: Modern, one version retry,
/// Legacy Streamable, and SSE. Bounds the deadline of commands that do not
/// call a tool.
const MAX_ATTEMPTS: u32 = 4;

/// The fields of each tool in the list; `tools <server> <tool>` shows all.
const LISTED_FIELDS: [&str; 5] = ["name", "title", "description", "inputSchema", "annotations"];

pub(crate) async fn run(
    args: ToolsArgs,
    context: &Context,
    deps: &Deps<'_>,
) -> Result<Reply, Error> {
    let name = ServerName::parse(&args.name)?;
    let tool = args.tool.as_deref();
    let entry = context.config.server(&name)?;
    let budget = Duration::from_secs(context.config.limits.request_timeout_secs) * MAX_ATTEMPTS;
    let deadline = Instant::now() + budget;
    let auth = Authorizer {
        context,
        deps,
        name: &name,
        entry,
        deadline,
    };
    authorized(auth, &|bearer| {
        Box::pin(attempt(
            context,
            deps,
            (&name, entry),
            tool,
            deadline,
            bearer,
        ))
    })
    .await
}

async fn attempt(
    context: &Context,
    deps: &Deps<'_>,
    (name, entry): (&ServerName, &ServerEntry),
    tool: Option<&str>,
    deadline: Instant,
    bearer: Option<String>,
) -> Result<Reply, Error> {
    let limits = &context.config.limits;
    let mut opened = connect(context, deps, (name, entry), deadline, bearer.as_deref()).await?;
    let listed = match deadline::check(Some(deadline)) {
        Ok(()) => list(opened.session.as_mut(), limits, name, tool).await,
        Err(error) => Err(error),
    };
    opened.session.close().await;
    let (value, warnings) = listed?;
    opened.warnings.extend(warnings);
    Ok(Reply {
        value,
        tool_error: false,
        warnings: opened.warnings,
    })
}

async fn list(
    session: &mut dyn McpSession,
    limits: &Limits,
    server: &ServerName,
    tool: Option<&str>,
) -> Result<(Value, Vec<String>), Error> {
    match tool {
        Some(tool) => find(session, limits, server, tool)
            .await
            .map(|(found, warnings)| (found.definition, warnings)),
        None => scan(session, limits, None).await.map(|list| {
            let tools = list.tools.iter().map(summary).collect();
            (Value::Array(tools), skipped(list.skipped))
        }),
    }
}

/// Finds one tool, paging only until it appears.
///
/// # Errors
/// `unknown_tool` if no valid tool has that name; the scan's errors.
pub(crate) async fn find(
    session: &mut dyn McpSession,
    limits: &Limits,
    server: &ServerName,
    tool: &str,
) -> Result<(Tool, Vec<String>), Error> {
    let list = scan(session, limits, Some(tool)).await?;
    let warnings = skipped(list.skipped);
    list.tools
        .into_iter()
        .next()
        .map(|found| (found, warnings))
        .ok_or_else(|| unknown_tool(server, tool))
}

fn summary(tool: &Tool) -> Value {
    let fields: Map<String, Value> = LISTED_FIELDS
        .iter()
        .filter_map(|field| {
            tool.definition
                .get(*field)
                .map(|value| ((*field).to_owned(), value.clone()))
        })
        .collect();
    Value::Object(fields)
}

/// Tool names are server-supplied, so the warning gives only the count.
fn skipped(count: u64) -> Vec<String> {
    (count > 0)
        .then(|| format!("skipped {count} tools with invalid names"))
        .into_iter()
        .collect()
}

fn unknown_tool(server: &ServerName, tool: &str) -> Error {
    Error::new(
        ErrorKind::UnknownTool,
        format!("{server} has no tool named {tool:?}; see `mcpjump tools {server}`"),
    )
}
