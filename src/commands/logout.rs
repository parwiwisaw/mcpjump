//! `mcpjump logout`: deletes the server's tokens and keeps its client
//! registration, so the next login does not register again.

use serde_json::{Value, json};

use crate::app::Deps;
use crate::auth::vault::Vault;
use crate::commands::Context;
use crate::config::validate::ServerName;
use crate::error::Error;

pub(crate) fn run(name: &str, context: &Context, deps: &Deps<'_>) -> Result<Value, Error> {
    let name = ServerName::parse(name)?;
    let vault = Vault {
        name: &name,
        context,
        stores: deps.stores,
        deadline: None,
    };
    let had_credentials = vault.forget_tokens()?;
    Ok(json!({ "server": name.as_str(), "logged_out": had_credentials }))
}
