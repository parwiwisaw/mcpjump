//! `mcpjump run`.

use std::time::Duration;

use serde_json::{Map, Value};
use tokio::time::Instant;

use crate::app::Deps;
use crate::auth::refresh::{Authorizer, authorized};
use crate::cli::{RunArgs, STDIN_PARAMS};
use crate::commands::connect::connect;
use crate::commands::tools::find;
use crate::commands::{Context, Reply};
use crate::config::limits::Limits;
use crate::config::model::ServerEntry;
use crate::config::validate::ServerName;
use crate::error::{Error, ErrorKind};
use crate::mcp::session::{McpSession, ToolResult};
use crate::mcp::validate::{check_params, validate};
use crate::sys::deadline;
use crate::sys::terminal::{Terminal, params_too_large};

/// The schema for a tool that declares none: any object.
static ANY_INPUT: Value = Value::Bool(true);

/// Checks the params, connects, finds the tool, validates the params
/// against its schema, and calls it once. The result is printed as the
/// server returned it; `isError: true` exits 1.
pub(crate) async fn run(args: RunArgs, context: &Context, deps: &Deps<'_>) -> Result<Reply, Error> {
    let name = ServerName::parse(&args.name)?;
    let limits = &context.config.limits;
    let text = params_text(args.params.as_deref(), limits, deps.terminal)?;
    let arguments = parse_params(&text, limits.max_json_depth)?;
    let timeout = args.timeout.unwrap_or(limits.tool_timeout_secs);
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let entry = context.config.server(&name)?;
    let auth = Authorizer {
        context,
        deps,
        name: &name,
        entry,
        deadline,
    };
    let tool = args.tool.as_str();
    authorized(auth, &|bearer| {
        let call = Call {
            name: &name,
            entry,
            tool,
            arguments: arguments.clone(),
            deadline,
        };
        Box::pin(attempt(context, deps, call, bearer))
    })
    .await
}

/// One tool call, repeated only after a 401 that rejected it unrun.
#[derive(Debug)]
struct Call<'a> {
    name: &'a ServerName,
    entry: &'a ServerEntry,
    tool: &'a str,
    arguments: Map<String, Value>,
    deadline: Instant,
}

async fn attempt(
    context: &Context,
    deps: &Deps<'_>,
    planned: Call<'_>,
    bearer: Option<String>,
) -> Result<Reply, Error> {
    let limits = &context.config.limits;
    let mut opened = connect(
        context,
        deps,
        (planned.name, planned.entry),
        planned.deadline,
        bearer.as_deref(),
    )
    .await?;
    let called = call(
        opened.session.as_mut(),
        limits,
        planned.name,
        planned.tool,
        planned.arguments,
        planned.deadline,
    )
    .await;
    opened.session.close().await;
    let (result, warnings) = called?;
    opened.warnings.extend(warnings);
    Ok(Reply {
        value: result.value,
        tool_error: result.is_error,
        warnings: opened.warnings,
    })
}

async fn call(
    session: &mut dyn McpSession,
    limits: &Limits,
    server: &ServerName,
    tool: &str,
    arguments: Map<String, Value>,
    command_deadline: Instant,
) -> Result<(ToolResult, Vec<String>), Error> {
    let (found, warnings) = deadline::dispatch(Some(command_deadline), || {
        find(session, limits, server, tool)
    })
    .await?;
    let schema = found.definition.get("inputSchema").unwrap_or(&ANY_INPUT);
    let timeout = Duration::from_secs(limits.validation_timeout_secs);
    validate(
        schema,
        &Value::Object(arguments.clone()),
        limits.max_json_depth,
        timeout,
    )?;
    let result = deadline::dispatch(Some(command_deadline), || {
        session.call_tool(tool, arguments)
    })
    .await?;
    Ok((result, warnings))
}

/// The params text: inline, from stdin with `-`, or `{}` when absent.
fn params_text(
    raw: Option<&str>,
    limits: &Limits,
    terminal: &dyn Terminal,
) -> Result<String, Error> {
    match raw {
        None => Ok("{}".to_owned()),
        Some(STDIN_PARAMS) => terminal.read_stdin(
            limits.max_params_bytes,
            Duration::from_secs(limits.stdin_timeout_secs),
        ),
        Some(inline)
            if u64::try_from(inline.len()).unwrap_or(u64::MAX) > limits.max_params_bytes =>
        {
            Err(params_too_large(limits.max_params_bytes))
        }
        Some(inline) => Ok(inline.to_owned()),
    }
}

/// Params echo no input back: they may hold secrets.
fn parse_params(text: &str, max_depth: u64) -> Result<Map<String, Value>, Error> {
    serde_json::from_str::<Value>(text)
        .map_err(|_| Error::new(ErrorKind::InvalidParams, "params are not valid JSON"))
        .and_then(|params| check_params(params, max_depth))
}
