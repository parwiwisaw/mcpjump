//! `mcpjump list`.

use serde_json::{Value, json};

use crate::commands::Context;
use crate::config::model::Backend;

pub(crate) fn run(context: &Context) -> Value {
    context
        .config
        .servers
        .iter()
        .map(|(name, entry)| {
            json!({
                "name": name.as_str(),
                "url": entry.spec.url().as_str(),
                "transport": entry.spec.transport(),
                "generation": entry.generation,
                "credentials": entry.credentials.map(Backend::label),
            })
        })
        .collect()
}
