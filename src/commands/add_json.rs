//! `mcpjump add-json`: a server from a Claude Code `mcp add-json` definition.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::Value;

use crate::cli::AddJsonArgs;
use crate::commands::{Context, add};
use crate::config::model::{ServerSpec, Transport};
use crate::config::validate::{HeaderTemplate, ServerName};
use crate::error::{Error, ErrorKind};

/// Claude Code's remote-server definition. `timeout` and `alwaysLoad` are
/// accepted and ignored; the fields mcpjump cannot honor are rejected.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Definition {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    headers_helper: Option<IgnoredAny>,
    #[serde(rename = "timeout")]
    _timeout: Option<IgnoredAny>,
    #[serde(rename = "alwaysLoad")]
    _always_load: Option<IgnoredAny>,
    #[serde(default)]
    oauth: OAuth,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct OAuth {
    client_id: Option<String>,
    #[serde(default)]
    callback_port: u16,
    auth_server_metadata_url: Option<IgnoredAny>,
    scopes: Option<IgnoredAny>,
}

pub(crate) fn run(args: &AddJsonArgs, context: &Context) -> Result<Value, Error> {
    let name = ServerName::parse(&args.name)?;
    let spec = parse_definition(&args.json)?;
    add::save(context, &name, &spec)
}

fn parse_definition(json: &str) -> Result<ServerSpec, Error> {
    let definition: Definition = serde_json::from_str(json).map_err(|error| {
        invalid(&format!(
            "invalid server definition at line {} column {}",
            error.line(),
            error.column()
        ))
    })?;
    let transport = match definition.kind.as_str() {
        "http" | "streamable-http" => Transport::Http,
        "sse" => Transport::Sse,
        _ => {
            return Err(invalid(
                "unsupported type; mcpjump supports http, streamable-http and sse",
            ));
        }
    };
    let unsupported = [
        ("headersHelper", definition.headers_helper.is_some()),
        (
            "oauth.authServerMetadataUrl",
            definition.oauth.auth_server_metadata_url.is_some(),
        ),
        ("oauth.scopes", definition.oauth.scopes.is_some()),
    ];
    if let Some((field, _)) = unsupported.iter().find(|(_, present)| *present) {
        return Err(invalid(&format!("{field} is not supported by mcpjump")));
    }
    let headers = definition
        .headers
        .iter()
        .map(|(name, value)| HeaderTemplate::parse(name, value))
        .collect::<Result<Vec<_>, _>>()?;
    ServerSpec::new(
        &definition.url,
        transport,
        headers,
        definition.oauth.client_id,
        definition.oauth.callback_port,
    )
}

fn invalid(message: &str) -> Error {
    Error::new(ErrorKind::InvalidDefinition, message)
}
