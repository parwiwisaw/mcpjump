//! Opens a session to a configured server, and remembers the protocol
//! generation that answered.

use tokio::time::Instant;

use crate::app::Deps;
use crate::commands::Context;
use crate::config::document;
use crate::config::model::{Generation, ServerEntry};
use crate::config::validate::ServerName;
use crate::error::Error;
use crate::mcp::connector::Target;
use crate::mcp::session::McpSession;

/// An open session and the warnings collected while opening it.
#[derive(Debug)]
pub(crate) struct Session {
    pub(crate) session: Box<dyn McpSession>,
    pub(crate) warnings: Vec<String>,
}

/// Connects to server `name`, configured as `entry`, under `deadline`,
/// sending `bearer` as the `Authorization` header when given.
///
/// # Errors
/// Header expansion errors and the connector's errors.
pub(crate) async fn connect(
    context: &Context,
    deps: &Deps<'_>,
    (name, entry): (&ServerName, &ServerEntry),
    deadline: Instant,
    bearer: Option<&str>,
) -> Result<Session, Error> {
    let mut target = target(entry, context, deps, deadline)?;
    target
        .headers
        .extend(bearer.map(|token| ("Authorization".to_owned(), format!("Bearer {token}"))));
    let connection = deps.connector.connect(target).await?;
    let warnings = remember(context, name, entry.generation, connection.generation);
    Ok(Session {
        session: connection.session,
        warnings,
    })
}

fn target(
    entry: &ServerEntry,
    context: &Context,
    deps: &Deps<'_>,
    deadline: Instant,
) -> Result<Target, Error> {
    let spec = &entry.spec;
    let headers = spec
        .headers()
        .iter()
        .map(|header| {
            header
                .expand(deps.env)
                .map(|value| (header.name().to_owned(), value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Target {
        url: spec.url().clone(),
        transport: spec.transport(),
        generation: entry.generation,
        headers,
        limits: context.config.limits.clone(),
        deadline,
    })
}

/// Saves a newly detected generation. The command has already connected,
/// so a failed save is a warning, not an error.
fn remember(
    context: &Context,
    name: &ServerName,
    saved: Option<Generation>,
    found: Generation,
) -> Vec<String> {
    if saved == Some(found) {
        return Vec::new();
    }
    let lock_wait = context.config.limits.lock_wait();
    context
        .file
        .update(lock_wait, &|doc| document::set_generation(doc, name, found))
        .err()
        .map(|error| {
            format!(
                "could not save the detected protocol generation: {}",
                error.message()
            )
        })
        .into_iter()
        .collect()
}
