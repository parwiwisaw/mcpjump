//! Edits to the parsed config document. Each edit touches only its own keys,
//! so the user's comments and layout elsewhere survive.

use toml_edit::{DocumentMut, InlineTable, Item, Table, value};

use crate::config::model::{Backend, Generation, ServerSpec, unknown_server};
use crate::config::validate::ServerName;
use crate::error::{Error, ErrorKind};

/// Adds `[servers.<name>]` with the fields the user defined.
///
/// # Errors
/// `server_exists` if the name is taken; `config_invalid` if `servers` is not a table.
pub fn insert_server(
    doc: &mut DocumentMut,
    name: &ServerName,
    spec: &ServerSpec,
) -> Result<(), Error> {
    let mut implicit = Table::new();
    implicit.set_implicit(true);
    let servers = doc
        .entry("servers")
        .or_insert(Item::Table(implicit))
        .as_table_like_mut()
        .ok_or_else(servers_not_a_table)?;
    if servers.contains_key(name.as_str()) {
        return Err(Error::new(
            ErrorKind::ServerExists,
            format!(
                "a server named {:?} already exists; remove it first",
                name.as_str()
            ),
        ));
    }
    servers.insert(name.as_str(), Item::Table(server_table(spec)));
    Ok(())
}

/// Removes `[servers.<name>]`.
///
/// # Errors
/// `unknown_server` if there is no such entry.
pub fn remove_server(doc: &mut DocumentMut, name: &ServerName) -> Result<(), Error> {
    doc.get_mut("servers")
        .and_then(Item::as_table_like_mut)
        .and_then(|servers| servers.remove(name.as_str()))
        .map(drop)
        .ok_or_else(|| unknown_server(name))
}

/// The credential backend recorded for `[servers.<name>]`, read inside the
/// config lock so it cannot change before the caller acts on it.
///
/// # Errors
/// `unknown_server` if there is no such entry; `config_invalid` for a value
/// other than `keyring` or `file`.
pub fn credentials(doc: &DocumentMut, name: &ServerName) -> Result<Option<Backend>, Error> {
    let server = doc
        .get("servers")
        .and_then(Item::as_table_like)
        .and_then(|servers| servers.get(name.as_str()))
        .and_then(Item::as_table_like)
        .ok_or_else(|| unknown_server(name))?;
    match server.get("credentials").map(Item::as_str) {
        None => Ok(None),
        Some(Some("keyring")) => Ok(Some(Backend::Keyring)),
        Some(Some("file")) => Ok(Some(Backend::File)),
        Some(_) => Err(Error::new(
            ErrorKind::ConfigInvalid,
            format!(
                "servers.{}.credentials: expected \"keyring\" or \"file\"",
                name.as_str()
            ),
        )),
    }
}

/// Records the protocol generation detected for `[servers.<name>]`.
///
/// # Errors
/// `unknown_server` if there is no such entry, or it is not a table.
pub fn set_generation(
    doc: &mut DocumentMut,
    name: &ServerName,
    generation: Generation,
) -> Result<(), Error> {
    doc.get_mut("servers")
        .and_then(Item::as_table_like_mut)
        .and_then(|servers| servers.get_mut(name.as_str()))
        .and_then(Item::as_table_like_mut)
        .map(|server| server.insert("generation", value(generation.as_str())))
        .map(drop)
        .ok_or_else(|| unknown_server(name))
}

/// Records the credential backend used at login for `[servers.<name>]`.
///
/// # Errors
/// `unknown_server` if there is no such entry, or it is not a table.
pub fn set_credentials(
    doc: &mut DocumentMut,
    name: &ServerName,
    backend: Backend,
) -> Result<(), Error> {
    let recorded = match backend {
        Backend::Keyring => "keyring",
        Backend::File => "file",
    };
    doc.get_mut("servers")
        .and_then(Item::as_table_like_mut)
        .and_then(|servers| servers.get_mut(name.as_str()))
        .and_then(Item::as_table_like_mut)
        .map(|server| server.insert("credentials", value(recorded)))
        .map(drop)
        .ok_or_else(|| unknown_server(name))
}

fn servers_not_a_table() -> Error {
    Error::new(ErrorKind::ConfigInvalid, "servers: expected a table")
}

fn server_table(spec: &ServerSpec) -> Table {
    let mut table = Table::new();
    table.insert("url", value(spec.url().as_str()));
    table.insert("transport", value(spec.transport().as_str()));
    if !spec.headers().is_empty() {
        let mut headers = InlineTable::new();
        for header in spec.headers() {
            headers.insert(header.name(), header.raw_value().into());
        }
        table.insert("headers", value(headers));
    }
    if let Some(client_id) = spec.client_id() {
        table.insert("client_id", value(client_id));
    }
    if spec.callback_port() != 0 {
        table.insert("callback_port", value(i64::from(spec.callback_port())));
    }
    table
}
