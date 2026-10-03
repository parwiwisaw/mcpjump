//! `mcpjump add`.

use serde_json::{Value, json};

use crate::cli::AddArgs;
use crate::commands::Context;
use crate::config::document;
use crate::config::model::ServerSpec;
use crate::config::validate::{HeaderTemplate, ServerName};
use crate::error::Error;

pub(crate) fn run(args: AddArgs, context: &Context) -> Result<Value, Error> {
    let name = ServerName::parse(&args.name)?;
    let headers = args
        .headers
        .iter()
        .map(|header| HeaderTemplate::parse_arg(header))
        .collect::<Result<Vec<_>, _>>()?;
    let spec = ServerSpec::new(
        &args.url,
        args.transport,
        headers,
        args.client_id,
        args.callback_port,
    )?;
    save(context, &name, &spec)
}

/// Saves a new server entry and returns the `add` result.
pub(crate) fn save(
    context: &Context,
    name: &ServerName,
    spec: &ServerSpec,
) -> Result<Value, Error> {
    context
        .file
        .update(context.config.limits.lock_wait(), &|doc| {
            document::insert_server(doc, name, spec)
        })?;
    Ok(json!({
        "name": name.as_str(),
        "url": spec.url().as_str(),
        "transport": spec.transport(),
    }))
}
