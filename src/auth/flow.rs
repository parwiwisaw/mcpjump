//! The browser login, as ordered steps: probe, discover, register (with
//! the callback listener bound), authorize, await the code, exchange it,
//! and store the tokens. Each step returns early with its own error.

use std::time::Duration;

use futures::{TryFutureExt, future};
use serde_json::json;
use tokio::sync::mpsc::{self, Receiver};
use tokio::time::{Instant, timeout_at};
use url::Url;

use crate::app::Deps;
use crate::auth::callback::{Callback, Verdict};
use crate::auth::challenge::Challenge;
use crate::auth::discovery::{AuthServer, Discovered, discover};
use crate::auth::http::AuthHttp;
use crate::auth::loopback::serve;
use crate::auth::paste::{MAX_PASTES, forward};
use crate::auth::pkce::{self, Secrets};
use crate::auth::refresh::has_static_authorization;
use crate::auth::registration::{Choice, Registered, register};
use crate::auth::token::{Binding, Grant, redeem};
use crate::auth::vault::Vault;
use crate::commands::connect::connect;
use crate::commands::{Console, Context, Reply};
use crate::config::model::ServerEntry;
use crate::config::validate::ServerName;
use crate::error::{Error, ErrorKind};
use crate::store::RecordKind;
use crate::store::record::{TokenRecord, is_scope};

/// Protocol attempts the probe may make, as for `tools`.
const PROBE_ATTEMPTS: u32 = 4;

/// Most scopes one login requests.
const MAX_REQUESTED_SCOPES: usize = 64;

/// What one login needs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Login<'a> {
    pub(crate) context: &'a Context,
    pub(crate) deps: &'a Deps<'a>,
    pub(crate) name: &'a ServerName,
    pub(crate) open_browser: bool,
}

/// The authorization code and the issuer the callback named.
#[derive(Debug)]
struct Code {
    code: String,
    iss: Option<String>,
}

/// Logs in to the server, or reports that it needs no login.
///
/// # Errors
/// `usage` for a server with a static `Authorization` header; the probe's
/// own error when it fails for another reason than authorization; the
/// discovery, registration, callback, token and store errors.
pub(crate) async fn login(login: Login<'_>, console: &mut Console<'_>) -> Result<Reply, Error> {
    let entry = login.context.config.server(login.name)?;
    if has_static_authorization(&entry.spec) {
        return Err(Error::new(
            ErrorKind::Usage,
            format!(
                "{} sends a static Authorization header, so mcpjump does not log in to it",
                login.name
            ),
        ));
    }
    let Some(challenge) = probe(login, entry).await? else {
        let value =
            json!({ "server": login.name.as_str(), "logged_in": false, "auth_required": false });
        return Ok(Reply::from(value));
    };
    let vault = Vault {
        name: login.name,
        context: login.context,
        stores: login.deps.stores,
    };
    let hint = challenge.resource_metadata.as_ref();
    let (http, discovered) = future::ready(AuthHttp::start(&login.context.config.limits))
        .and_then(|http| async move {
            let discovered = discover(&http, entry.spec.url(), hint).await;
            discovered.map(|discovered| (http, discovered))
        })
        .await?;
    let mut warnings = Vec::new();
    let registered = client(login, &http, entry, &discovered, vault, &mut warnings).await?;
    let stored = tolerate(vault.load::<TokenRecord>(entry.credentials, RecordKind::Tokens))?;
    let scopes = requested_scopes(&challenge, &discovered, stored.as_ref());
    let tokens = future::ready(pkce::secrets())
        .and_then(|secrets| authorize(login, console, &discovered, registered, &scopes, secrets))
        .await?;
    let (backend, notice) = vault.save(RecordKind::Tokens, &tokens)?;
    warnings.extend(notice);
    let value = json!({
        "server": login.name.as_str(),
        "logged_in": true,
        "backend": backend.label(),
        "scopes": tokens.scopes,
    });
    Ok(Reply {
        value,
        tool_error: false,
        warnings,
    })
}

/// An unauthenticated connection and one page of tools. `None` when the
/// server answers without a login; its challenge when it asks for one.
async fn probe(login: Login<'_>, entry: &ServerEntry) -> Result<Option<Challenge>, Error> {
    let limits = &login.context.config.limits;
    let budget = Duration::from_secs(limits.request_timeout_secs) * PROBE_ATTEMPTS;
    let probed = match connect(
        login.context,
        login.deps,
        (login.name, entry),
        Instant::now() + budget,
        None,
    )
    .await
    {
        Ok(mut opened) => {
            let listed = opened.session.list_tools_page(None).await.map(drop);
            opened.session.close().await;
            listed
        }
        Err(error) => Err(error),
    };
    let Err(error) = probed else {
        return Ok(None);
    };
    error
        .challenge()
        .filter(|challenge| challenge.unauthorized() || challenge.insufficient_scope())
        .cloned()
        .map(Some)
        .ok_or(error)
}

/// Chooses the client, binds its listener, and saves a new registration
/// at once, so a failed login does not register again next time.
async fn client(
    login: Login<'_>,
    http: &AuthHttp,
    entry: &ServerEntry,
    discovered: &Discovered,
    vault: Vault<'_>,
    warnings: &mut Vec<String>,
) -> Result<Registered, Error> {
    let stored = tolerate(vault.load(entry.credentials, RecordKind::Registration))?;
    let choice = Choice {
        server: &discovered.server,
        client_id: entry.spec.client_id(),
        callback_port: entry.spec.callback_port(),
        metadata_url: login.context.config.settings.client_metadata_url.as_ref(),
    };
    let registered = register(http, choice, stored).await?;
    if registered.changed {
        warnings.extend(vault.save(RecordKind::Registration, &registered.client)?.1);
    }
    Ok(registered)
}

/// A corrupt record is ignored: the login replaces it.
fn tolerate<R>(loaded: Result<Option<R>, Error>) -> Result<Option<R>, Error> {
    match loaded {
        Err(error) if error.kind() == ErrorKind::CredentialInvalid => Ok(None),
        other => other,
    }
}

/// The challenge's scope, else the advertised scopes, plus the scopes of
/// a stored token for the same resource and issuer and its pending ones.
fn requested_scopes(
    challenge: &Challenge,
    discovered: &Discovered,
    stored: Option<&TokenRecord>,
) -> Vec<String> {
    let base: Vec<String> = challenge.scope.as_deref().map_or_else(
        || discovered.scopes_supported.clone(),
        |scope| scope.split(' ').map(str::to_owned).collect(),
    );
    let kept = stored
        .filter(|tokens| {
            tokens.resource == discovered.resource && tokens.issuer == discovered.server.issuer
        })
        .map(|tokens| [tokens.scopes.as_slice(), tokens.pending_scopes.as_slice()].concat())
        .unwrap_or_default();
    let mut scopes: Vec<String> = Vec::with_capacity(MAX_REQUESTED_SCOPES);
    for scope in base.into_iter().chain(kept).filter(|scope| is_scope(scope)) {
        if scopes.len() < MAX_REQUESTED_SCOPES && !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    scopes
}

/// Sends the user to the authorization endpoint, waits for the code, and
/// exchanges it.
async fn authorize(
    login: Login<'_>,
    console: &mut Console<'_>,
    discovered: &Discovered,
    registered: Registered,
    scopes: &[String],
    secrets: Secrets,
) -> Result<TokenRecord, Error> {
    let Secrets { state, verifier } = secrets;
    let client = registered.client;
    let url = authorize_url(
        discovered,
        &client.client_id,
        &client.redirect_uri,
        scopes,
        &state,
        &verifier,
    );
    let (sender, mut verdicts) = mpsc::channel(4);
    let listener = registered.listener;
    let server = tokio::spawn(serve(
        listener.socket,
        listener.port,
        state.clone(),
        sender.clone(),
    ));
    let pasting = login.deps.terminal.paste().map(|lines| {
        tokio::spawn(forward(
            lines,
            client.redirect_uri.clone(),
            state.clone(),
            sender,
        ))
    });
    announce(login, console, &url, pasting.is_some());
    let limits = &login.context.config.limits;
    let deadline = Instant::now() + Duration::from_secs(limits.login_timeout_secs);
    let code = receive(&mut verdicts, deadline, limits.login_timeout_secs, console).await;
    server.abort();
    pasting.iter().for_each(tokio::task::JoinHandle::abort);
    let code = code?;
    check_iss(code.iss.as_deref(), &discovered.server)?;
    let binding = Binding {
        client: &client,
        resource: &discovered.resource,
        token_endpoint: &discovered.server.token_endpoint,
    };
    let grant = Grant::Code {
        code: &code.code,
        verifier: &verifier,
        redirect_uri: client.redirect_uri.as_str(),
    };
    let now = login.deps.clock.now_unix();
    future::ready(AuthHttp::start(limits))
        .and_then(|http| async move { redeem(&http, binding, grant, None, scopes, now).await })
        .await
}

fn authorize_url(
    discovered: &Discovered,
    client_id: &str,
    redirect_uri: &Url,
    scopes: &[String],
    state: &str,
    verifier: &str,
) -> Url {
    let mut url = discovered.server.authorization_endpoint.clone();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri.as_str())
        .append_pair("code_challenge", &pkce::challenge(verifier))
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state)
        .append_pair("resource", discovered.resource.as_str());
    if !scopes.is_empty() {
        url.query_pairs_mut()
            .append_pair("scope", &scopes.join(" "));
    }
    url
}

/// Prints the URL, then opens the browser. A browser that does not open
/// is a warning: the printed URL still works.
fn announce(login: Login<'_>, console: &mut Console<'_>, url: &Url, pasting: bool) {
    let paste_hint = if pasting {
        "\nIf the browser is on another machine, paste the URL it was sent to here."
    } else {
        ""
    };
    console.notice(
        &format!("To log in, open:\n  {url}{paste_hint}"),
        &json!({ "authorize": { "url": url.as_str() } }),
    );
    if login.open_browser {
        let timeout = Duration::from_secs(login.context.config.limits.browser_timeout_secs);
        if let Err(reason) = login.deps.browser.open(url, timeout) {
            console.warn(&format!("could not open a browser: {reason}"));
        }
    }
}

/// The first code from the listener or a paste. Rejected pastes are
/// reported and waited past, at most [`MAX_PASTES`] of them.
async fn receive(
    verdicts: &mut Receiver<Verdict>,
    deadline: Instant,
    timeout_secs: u64,
    console: &mut Console<'_>,
) -> Result<Code, Error> {
    for _ in 0..=MAX_PASTES {
        let verdict = timeout_at(deadline, verdicts.recv())
            .await
            .ok()
            .flatten()
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::LoginTimeout,
                    format!("the login did not finish within login_timeout_secs ({timeout_secs})"),
                )
            })?;
        match verdict {
            Ok(Callback::Code { code, iss }) => return Ok(Code { code, iss }),
            Ok(Callback::Denied(error)) => {
                return Err(Error::new(
                    ErrorKind::AuthRequired,
                    format!("the authorization server refused the login: {error:?}"),
                ));
            }
            Err(reason) => console.warn(&format!("ignored the pasted URL: {reason}")),
        }
    }
    Err(Error::new(
        ErrorKind::AuthRequired,
        "too many invalid pasted URLs; run the login again",
    ))
}

/// The callback's `iss` (RFC 9207): required when the server advertises
/// it, and it must name the server whenever it is present.
fn check_iss(iss: Option<&str>, server: &AuthServer) -> Result<(), Error> {
    match iss {
        Some(iss) if iss == server.issuer_text => Ok(()),
        None if !server.iss_required => Ok(()),
        _ => Err(Error::new(
            ErrorKind::ProtocolError,
            "the authorization response does not name the expected authorization server (iss)",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::OutputFormat;

    #[tokio::test]
    async fn a_login_that_gets_no_code_in_time_times_out() {
        let (_sender, mut verdicts) = mpsc::channel::<Verdict>(1);
        let mut err = Vec::new();
        let mut console = Console::new(&mut err, OutputFormat::Json);
        let error = receive(&mut verdicts, Instant::now(), 30, &mut console)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::LoginTimeout);
        assert_eq!(
            error.message(),
            "the login did not finish within login_timeout_secs (30)"
        );
    }
}
