//! Streamable HTTP negotiation and unchanged handshake classifications.

use rmcp::model::{DiscoverResult, ErrorData, InitializeResult};
use serde_json::json;

use crate::error::{Error, ErrorKind};
use crate::mcp::client_session::Opened;
use crate::mcp::endpoint::Endpoint;
use crate::mcp::rpc::{Answer, protocol_error};

/// Offers Modern or Legacy Streamable, with at most one supported-version retry.
pub(crate) async fn open(endpoint: &Endpoint, modern: bool) -> Result<Opened, Error> {
    let mut opened = Opened::new(modern);
    if modern {
        discover(endpoint, &mut opened).await?;
    } else {
        initialize(endpoint, &mut opened, "2025-11-25").await?;
    }
    Ok(opened)
}

/// Only -32022 naming our preferred version permits a second discover POST.
async fn discover(endpoint: &Endpoint, opened: &mut Opened) -> Result<(), Error> {
    let origin = endpoint.origin();
    let first = opened
        .request(endpoint, "server/discover", json!({}), false)
        .await?;
    let answer = match first {
        Answer::Error(error) if error.code.0 == -32022 && shares_version(&error) => {
            opened
                .request(endpoint, "server/discover", json!({}), false)
                .await?
        }
        other => other,
    };
    match answer {
        Answer::Result(value) => {
            let result: DiscoverResult = serde_json::from_value(value)
                .map_err(|_| protocol_error(&origin, "did not complete the MCP handshake"))?;
            if result
                .supported_versions
                .iter()
                .any(|version| version.as_str() == "2026-07-28")
            {
                Ok(())
            } else {
                Err(unsupported(&origin))
            }
        }
        Answer::Error(error) => Err(init_error(&error, true, &origin)),
    }
}

/// Legacy handshakes offer their transport's version before notifying initialized.
pub(crate) async fn initialize(
    endpoint: &Endpoint,
    opened: &mut Opened,
    version: &str,
) -> Result<(), Error> {
    let origin = endpoint.origin();
    let params = json!({"protocolVersion":version,"capabilities":{},"clientInfo":{"name":"mcpjump","version":env!("CARGO_PKG_VERSION")}});
    let result = match opened
        .request(endpoint, "initialize", params, false)
        .await?
    {
        Answer::Result(value) => serde_json::from_value::<InitializeResult>(value)
            .map_err(|_| protocol_error(&origin, "did not complete the MCP handshake"))?,
        Answer::Error(error) => return Err(init_error(&error, false, &origin)),
    };
    if opened.sse.is_none() {
        let version = match result.protocol_version.as_str() {
            "2025-03-26" => "2025-03-26",
            "2025-06-18" => "2025-06-18",
            "2025-11-25" => "2025-11-25",
            _ => return Err(unsupported(&origin)),
        };
        opened.version = Some(version);
    }
    opened
        .post(
            endpoint,
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            "notifications/initialized",
            endpoint.bounds.deadline(false),
        )
        .await?;
    Ok(())
}

/// Modern rejects the request itself only with header/capability errors.
/// Other correlated errors signal Legacy; Legacy RPC errors remain server errors.
fn init_error(data: &ErrorData, modern: bool, origin: &str) -> Error {
    if modern && ![-32020, -32021].contains(&data.code.0) {
        return unsupported(origin);
    }
    Error::new(
        ErrorKind::ServerError,
        format!(
            "{origin} rejected the MCP handshake with JSON-RPC error {}",
            data.code.0
        ),
    )
}

/// A completed rejection of this generation allows the probe to advance.
fn unsupported(origin: &str) -> Error {
    Error::new(
        ErrorKind::UnsupportedServer,
        format!("{origin} does not speak this MCP protocol generation"),
    )
}

/// The preferred version must occur in a typed supported-version array.
fn shares_version(error: &ErrorData) -> bool {
    error
        .data
        .as_ref()
        .and_then(|data| data.get("supported"))
        .and_then(|value| serde_json::from_value::<Vec<String>>(value.clone()).ok())
        .is_some_and(|versions| versions.iter().any(|version| version == "2026-07-28"))
}
