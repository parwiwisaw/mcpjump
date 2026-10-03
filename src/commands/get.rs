//! `mcpjump get`.

use serde_json::{Map, Value, json};

use crate::commands::Context;
use crate::config::model::Backend;
use crate::config::validate::ServerName;
use crate::error::Error;

/// Shown instead of every header value, which may be a secret even when it
/// is a `${VAR}` reference with a literal default.
const REDACTED: &str = "[redacted]";

pub(crate) fn run(name: &str, context: &Context) -> Result<Value, Error> {
    let name = ServerName::parse(name)?;
    let entry = context.config.server(&name)?;
    let spec = &entry.spec;
    let headers: Map<String, Value> = spec
        .headers()
        .iter()
        .map(|header| (header.name().to_owned(), REDACTED.into()))
        .collect();
    Ok(json!({
        "name": name.as_str(),
        "url": spec.url().as_str(),
        "transport": spec.transport(),
        "generation": entry.generation,
        "headers": headers,
        "client_id": spec.client_id(),
        "callback_port": spec.callback_port(),
        "credentials": entry.credentials.map(Backend::label),
    }))
}
