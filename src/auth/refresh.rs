//! Bearer tokens for `run` and `tools`: a token about to expire is
//! refreshed first, a 401 gets one refresh and one retry, and a 403 asking
//! for more scope is remembered for the next login. Every refresh holds the
//! server lock and re-reads the record, so two processes never spend the
//! same refresh token.

use futures::TryFutureExt;
use futures::future::{self, LocalBoxFuture};

use crate::app::Deps;
use crate::auth::challenge::Challenge;
use crate::auth::discovery::resource_matches;
use crate::auth::http::AuthHttp;
use crate::auth::token::{Binding, Grant, redeem};
use crate::auth::vault::Vault;
use crate::commands::Context;
use crate::config::model::{ServerEntry, ServerSpec};
use crate::config::validate::ServerName;
use crate::error::{Error, ErrorKind};
use crate::store::record::{
    self, MAX_PENDING_SCOPE_BYTES, RegistrationRecord, TokenRecord, is_scope,
};
use crate::store::{CredentialStore, RecordKind, lock};

/// A token that expires within this many seconds is refreshed first.
pub(crate) const EXPIRY_WINDOW_SECS: u64 = 60;

/// One attempt of a command's work, given the bearer token to send.
pub(crate) type Work<'a, T> = dyn Fn(Option<String>) -> LocalBoxFuture<'a, Result<T, Error>> + 'a;

/// What the refresh needs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Authorizer<'a> {
    pub(crate) context: &'a Context,
    pub(crate) deps: &'a Deps<'a>,
    pub(crate) name: &'a ServerName,
    pub(crate) entry: &'a ServerEntry,
}

/// Whether the server is configured with its own `Authorization` header,
/// which turns mcpjump's OAuth off for it.
pub(crate) fn has_static_authorization(spec: &ServerSpec) -> bool {
    spec.headers()
        .iter()
        .any(|header| header.name().eq_ignore_ascii_case("authorization"))
}

/// Runs `work` with the stored token, if any.
///
/// # Errors
/// `auth_required` with a login hint when the token is missing, unusable,
/// refused, or lacks scope; the store and lock errors; `work`'s errors.
pub(crate) async fn authorized<'a, T>(
    auth: Authorizer<'a>,
    work: &Work<'a, T>,
) -> Result<T, Error> {
    let entry = auth.entry;
    let vault = auth.vault();
    let backend = entry
        .credentials
        .filter(|_| !has_static_authorization(&entry.spec));
    let Some(backend) = backend else {
        return work(None).await.map_err(|error| hint(error, auth.name));
    };
    let store = vault.open(backend)?.store;
    let Some(tokens) = vault.read::<TokenRecord>(&*store, RecordKind::Tokens)? else {
        return work(None).await.map_err(|error| hint(error, auth.name));
    };
    check_binding(&tokens, &entry.spec, auth.name)?;
    let tokens = if expiring(&tokens, auth.deps.clock.now_unix()) {
        renew(auth, &*store, &tokens).await?
    } else {
        tokens
    };
    let first = work(Some(tokens.access_token.clone())).await;
    let challenge = first.as_ref().err().and_then(Error::challenge).cloned();
    match challenge {
        Some(challenge) if challenge.unauthorized() => {
            let renewed = renew(auth, &*store, &tokens).await?;
            work(Some(renewed.access_token))
                .await
                .map_err(|error| hint(error, auth.name))
        }
        Some(challenge) if challenge.insufficient_scope() => {
            remember_scope(auth, &*store, &challenge)?;
            first.map_err(|error| hint(error, auth.name))
        }
        _ => first,
    }
}

impl Authorizer<'_> {
    fn vault(&self) -> Vault<'_> {
        Vault {
            name: self.name,
            context: self.context,
            stores: self.deps.stores,
        }
    }
}

/// Whether the token expires within [`EXPIRY_WINDOW_SECS`] of `now`.
pub(crate) fn expiring(tokens: &TokenRecord, now: u64) -> bool {
    tokens
        .expires_at
        .is_some_and(|at| at.saturating_sub(now) <= EXPIRY_WINDOW_SECS)
}

/// A token is used only for the resource and client it was issued for.
fn check_binding(tokens: &TokenRecord, spec: &ServerSpec, name: &ServerName) -> Result<(), Error> {
    let same_client = spec
        .client_id()
        .is_none_or(|client_id| client_id == tokens.client_id);
    if resource_matches(&tokens.resource, spec.url()) && same_client {
        return Ok(());
    }
    Err(Error::new(
        ErrorKind::AuthRequired,
        format!(
            "the stored login of {name} was for another server URL or client; run `mcpjump login {name}`"
        ),
    ))
}

/// The current token under the server lock: another process's newer one,
/// else a refreshed one.
async fn renew(
    auth: Authorizer<'_>,
    store: &dyn CredentialStore,
    stale: &TokenRecord,
) -> Result<TokenRecord, Error> {
    let wait = auth.context.config.limits.lock_wait();
    let lock = lock::server_lock(auth.context.file.dir(), auth.name, wait)?;
    let renewed = renew_locked(auth, store, stale).await;
    lock::release(lock, &renewed);
    renewed.map_err(|error| hint(error, auth.name))
}

async fn renew_locked(
    auth: Authorizer<'_>,
    store: &dyn CredentialStore,
    stale: &TokenRecord,
) -> Result<TokenRecord, Error> {
    let vault = auth.vault();
    let current = vault
        .read::<TokenRecord>(store, RecordKind::Tokens)?
        .ok_or_else(|| expired("the login was removed"))?;
    if current.access_token != stale.access_token {
        return Ok(current);
    }
    let refresh_token = current
        .refresh_token
        .as_deref()
        .ok_or_else(|| expired("the token expired and cannot be refreshed"))?;
    let client = vault
        .read::<RegistrationRecord>(store, RecordKind::Registration)?
        .filter(|client| client.client_id == current.client_id && client.issuer == current.issuer)
        .ok_or_else(|| expired("the client the token was issued to is gone"))?;
    let binding = Binding {
        client: &client,
        resource: &current.resource,
        token_endpoint: &current.token_endpoint,
    };
    let grant = Grant::Refresh { refresh_token };
    let now = auth.deps.clock.now_unix();
    let previous = Some(&current);
    let renewed = future::ready(AuthHttp::start(&auth.context.config.limits))
        .and_then(|http| async move { redeem(&http, binding, grant, previous, &[], now).await })
        .await?;
    store.set(&vault.key(RecordKind::Tokens), &record::encode(&renewed))?;
    Ok(renewed)
}

/// Saves the scope a 403 asked for, so the next login requests it. A
/// scope that would pass [`MAX_PENDING_SCOPE_BYTES`] is not saved.
fn remember_scope(
    auth: Authorizer<'_>,
    store: &dyn CredentialStore,
    challenge: &Challenge,
) -> Result<(), Error> {
    let Some(scope) = challenge.scope.as_deref() else {
        return Ok(());
    };
    let vault = auth.vault();
    let wait = auth.context.config.limits.lock_wait();
    lock::with_server_lock(auth.context.file.dir(), auth.name, wait, &|| {
        let Some(mut tokens) = vault.read::<TokenRecord>(store, RecordKind::Tokens)? else {
            return Ok(());
        };
        for added in scope.split(' ').filter(|scope| is_scope(scope)) {
            let known = tokens
                .scopes
                .iter()
                .chain(&tokens.pending_scopes)
                .any(|s| s == added);
            if !known {
                tokens.pending_scopes.push(added.to_owned());
            }
        }
        if tokens.pending_scopes.join(" ").len() > MAX_PENDING_SCOPE_BYTES {
            return Ok(());
        }
        store.set(&vault.key(RecordKind::Tokens), &record::encode(&tokens))
    })
}

fn expired(reason: &str) -> Error {
    Error::new(ErrorKind::AuthRequired, reason)
}

/// Adds the login command to an `auth_required` error.
fn hint(error: Error, name: &ServerName) -> Error {
    if error.kind() != ErrorKind::AuthRequired {
        return error;
    }
    Error::new(
        ErrorKind::AuthRequired,
        format!("{}; run `mcpjump login {name}`", error.message()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_go_only_on_auth_errors() {
        let name = ServerName::parse("s").unwrap();
        let auth = hint(Error::new(ErrorKind::AuthRequired, "no"), &name);
        assert_eq!(auth.message(), "no; run `mcpjump login s`");
        let other = hint(Error::new(ErrorKind::Network, "down"), &name);
        assert_eq!(other.message(), "down");
    }
}
