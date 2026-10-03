//! `mcpjump remove`: deletes the server's credentials, then its config
//! entry. If the credentials cannot be deleted, nothing is removed, so no
//! secret is left behind without a config entry that names it.

use serde_json::{Value, json};
use toml_edit::DocumentMut;

use crate::app::Deps;
use crate::commands::Context;
use crate::config::document;
use crate::config::model::Backend;
use crate::config::validate::ServerName;
use crate::error::Error;
use crate::store::select::{self, Request};
use crate::store::{Key, RecordKind, lock};

pub(crate) fn run(name: &str, context: &Context, deps: &Deps<'_>) -> Result<Value, Error> {
    let name = ServerName::parse(name)?;
    context
        .file
        .update(context.config.limits.lock_wait(), &|doc| {
            remove(doc, &name, context, deps)
        })?;
    Ok(json!({ "removed": name.as_str() }))
}

/// Runs under the config lock, so the recorded backend cannot change.
fn remove(
    doc: &mut DocumentMut,
    name: &ServerName,
    context: &Context,
    deps: &Deps<'_>,
) -> Result<(), Error> {
    if let Some(backend) = document::credentials(doc, name)? {
        delete_credentials(name, backend, context, deps)?;
    }
    document::remove_server(doc, name)
}

fn delete_credentials(
    name: &ServerName,
    backend: Backend,
    context: &Context,
    deps: &Deps<'_>,
) -> Result<(), Error> {
    let limits = &context.config.limits;
    let config_dir = context.file.dir();
    let config_file = context.file.path();
    let request = Request {
        server: name,
        recorded: Some(backend),
        policy: context.config.settings.credential_store,
        config_dir,
        config_file: &config_file,
        limits,
    };
    lock::with_server_lock(config_dir, name, limits.lock_wait(), &|| {
        let selected = select::select(deps.stores, &request)?;
        RecordKind::ALL
            .into_iter()
            .try_for_each(|kind| selected.store.delete(&Key::new(name.clone(), kind)))
    })
}
