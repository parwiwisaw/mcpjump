//! The OAuth client mcpjump logs in as, in priority order: a pre-registered
//! client ID, a Client ID Metadata Document, a saved dynamic registration,
//! then Dynamic Client Registration (RFC 7591). The callback listener is
//! bound first, so the exact redirect URI is known when registering.

use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use serde_json::json;
use url::Url;

use crate::auth::discovery::AuthServer;
use crate::auth::http::{Answer, AuthHttp};
use crate::auth::loopback::{Listener, listen};
use crate::auth::token::refused;
use crate::error::{Error, ErrorKind};
use crate::store::record::{
    Record, RegistrationMethod, RegistrationRecord, TokenEndpointAuth, is_redirect,
};

/// Redirect URIs read from a client metadata document.
const MAX_REDIRECT_URIS: usize = 16;

/// What the login needs to choose a client.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Choice<'a> {
    pub(crate) server: &'a AuthServer,
    /// The client ID from `add --client-id`.
    pub(crate) client_id: Option<&'a str>,
    /// The callback port from `add --callback-port`; 0 picks one.
    pub(crate) callback_port: u16,
    /// `settings.client_metadata_url`.
    pub(crate) metadata_url: Option<&'a Url>,
}

/// The client to log in as, with its bound callback listener.
#[derive(Debug)]
pub(crate) struct Registered {
    pub(crate) client: RegistrationRecord,
    pub(crate) listener: Listener,
    /// Whether `client` differs from the stored registration.
    pub(crate) changed: bool,
}

#[derive(Debug, Deserialize)]
struct ClientInformation {
    client_id: String,
    client_secret: Option<String>,
    token_endpoint_auth_method: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClientMetadata {
    client_id: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

/// Chooses the client and binds its callback listener.
///
/// # Errors
/// `auth_required` when no way to register is left, or the registration
/// is refused; the HTTP and listener errors.
pub(crate) async fn register(
    http: &AuthHttp,
    choice: Choice<'_>,
    stored: Option<RegistrationRecord>,
) -> Result<Registered, Error> {
    let server = choice.server;
    let fresh = |client: RegistrationRecord, listener: Listener| Registered {
        changed: stored.as_ref() != Some(&client),
        client,
        listener,
    };
    if let Some(client_id) = choice.client_id {
        check_issuer(stored.as_ref(), client_id, server)?;
        let listener = listen(choice.callback_port).await?;
        let client = public(
            server,
            client_id,
            &listener,
            RegistrationMethod::Preregistered,
        );
        return Ok(fresh(client, listener));
    }
    if let Some(url) = choice.metadata_url.filter(|_| server.cimd) {
        let listener = metadata_listener(http, url).await?;
        let client = public(
            server,
            url.as_str(),
            &listener,
            RegistrationMethod::MetadataDocument,
        );
        return Ok(fresh(client, listener));
    }
    if let Some(reused) = reuse(server, stored.as_ref()).await {
        return Ok(reused);
    }
    let endpoint = server.registration_endpoint.as_ref().ok_or_else(|| {
        Error::new(
            ErrorKind::AuthRequired,
            "the authorization server offers no way to register mcpjump; \
             remove the server and add it again with --client-id",
        )
    })?;
    let listener = listen(choice.callback_port).await?;
    let client = dynamic(http, server, endpoint, &listener.redirect_uri).await?;
    Ok(fresh(client, listener))
}

/// A pre-registered client is bound to the issuer it was first used with;
/// it is never silently moved to another.
fn check_issuer(
    stored: Option<&RegistrationRecord>,
    client_id: &str,
    server: &AuthServer,
) -> Result<(), Error> {
    if stored.is_some_and(|stored| {
        stored.method == RegistrationMethod::Preregistered
            && stored.client_id == client_id
            && stored.issuer != server.issuer
    }) {
        return Err(Error::new(
            ErrorKind::AuthRequired,
            "the server now uses another authorization server than the one its client ID \
             was registered with; remove the server and add it again",
        ));
    }
    Ok(())
}

fn public(
    server: &AuthServer,
    client_id: &str,
    listener: &Listener,
    method: RegistrationMethod,
) -> RegistrationRecord {
    RegistrationRecord {
        issuer: server.issuer.clone(),
        client_id: client_id.to_owned(),
        client_secret: None,
        token_endpoint_auth_method: TokenEndpointAuth::None,
        redirect_uri: listener.redirect_uri.clone(),
        method,
    }
}

/// Binds the first free loopback port the metadata document lists.
async fn metadata_listener(http: &AuthHttp, url: &Url) -> Result<Listener, Error> {
    let answer = http.send(http.get(url)).await?;
    if answer.status != StatusCode::OK {
        return Err(answer.unexpected("the client metadata document"));
    }
    let metadata: ClientMetadata = answer.json("client metadata document")?;
    if metadata.client_id != url.as_str() {
        return Err(Error::new(
            ErrorKind::ProtocolError,
            "the client metadata document names another client_id than its URL",
        ));
    }
    let ports = metadata
        .redirect_uris
        .iter()
        .take(MAX_REDIRECT_URIS)
        .filter_map(|raw| Url::parse(raw).ok())
        .filter(is_redirect)
        .filter_map(|url| url.port());
    for port in ports {
        if let Ok(listener) = listen(port).await {
            return Ok(listener);
        }
    }
    Err(Error::new(
        ErrorKind::AuthRequired,
        "no redirect port in the client metadata document is free; close what uses it and retry",
    ))
}

/// The saved dynamic registration, if it is for this issuer and its port
/// is free.
async fn reuse(server: &AuthServer, stored: Option<&RegistrationRecord>) -> Option<Registered> {
    let stored = stored.filter(|stored| {
        stored.method == RegistrationMethod::Dynamic && stored.issuer == server.issuer
    })?;
    let listener = listen(stored.redirect_uri.port().unwrap_or_default())
        .await
        .ok()?;
    Some(Registered {
        client: stored.clone(),
        listener,
        changed: false,
    })
}

/// Registers mcpjump as a public native client. A server that accepts
/// only secret-based clients gets one retry with `client_secret_basic`.
async fn dynamic(
    http: &AuthHttp,
    server: &AuthServer,
    endpoint: &Url,
    redirect_uri: &Url,
) -> Result<RegistrationRecord, Error> {
    let first = post(http, endpoint, redirect_uri, "none").await?;
    let answer = if wants_secret(&first, server) {
        post(http, endpoint, redirect_uri, "client_secret_basic").await?
    } else {
        first
    };
    if answer.status != StatusCode::CREATED && answer.status != StatusCode::OK {
        return Err(match answer.status {
            StatusCode::BAD_REQUEST => refused(&answer, "the client registration"),
            _ => answer.unexpected("the client registration"),
        });
    }
    let information: ClientInformation = answer.json("client registration")?;
    let method = auth_method(
        information.client_secret.is_some(),
        information.token_endpoint_auth_method.as_deref(),
        &server.auth_methods,
    );
    let client = RegistrationRecord {
        issuer: server.issuer.clone(),
        client_id: information.client_id,
        client_secret: information.client_secret,
        token_endpoint_auth_method: method,
        redirect_uri: redirect_uri.clone(),
        method: RegistrationMethod::Dynamic,
    };
    if !client.is_valid() {
        return Err(Error::new(
            ErrorKind::ProtocolError,
            format!("{} returned an unusable client registration", answer.origin),
        ));
    }
    Ok(client)
}

async fn post(
    http: &AuthHttp,
    endpoint: &Url,
    redirect_uri: &Url,
    method: &str,
) -> Result<Answer, Error> {
    let body = json!({
        "client_name": "mcpjump",
        "redirect_uris": [redirect_uri.as_str()],
        "application_type": "native",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": method,
    });
    let request = http
        .post(endpoint)
        .header(CONTENT_TYPE, "application/json")
        .body(body.to_string());
    http.send(request).await
}

/// Whether the server refused a public client and supports only
/// secret-based ones.
fn wants_secret(answer: &Answer, server: &AuthServer) -> bool {
    answer.status == StatusCode::BAD_REQUEST
        && !server.auth_methods.iter().any(|method| method == "none")
        && answer
            .json::<ErrorResponse>("error response")
            .is_ok_and(|response| response.error == "invalid_client_metadata")
}

/// The method the server returned, else the first secret method it
/// advertises, else `client_secret_basic`. A client without a secret is
/// public.
fn auth_method(
    has_secret: bool,
    returned: Option<&str>,
    advertised: &[String],
) -> TokenEndpointAuth {
    let secret_method = |method: &str| match method {
        "client_secret_basic" => Some(TokenEndpointAuth::ClientSecretBasic),
        "client_secret_post" => Some(TokenEndpointAuth::ClientSecretPost),
        _ => None,
    };
    if !has_secret {
        return TokenEndpointAuth::None;
    }
    returned
        .and_then(secret_method)
        .or_else(|| advertised.iter().find_map(|method| secret_method(method)))
        .unwrap_or(TokenEndpointAuth::ClientSecretBasic)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn methods(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn the_auth_method_follows_the_server() {
        use TokenEndpointAuth::{ClientSecretBasic, ClientSecretPost};
        assert_eq!(
            auth_method(false, Some("client_secret_post"), &[]),
            TokenEndpointAuth::None
        );
        assert_eq!(
            auth_method(true, Some("client_secret_post"), &[]),
            ClientSecretPost
        );
        assert_eq!(
            auth_method(true, Some("client_secret_basic"), &[]),
            ClientSecretBasic
        );
        let post_only = methods(&["private_key_jwt", "client_secret_post"]);
        assert_eq!(
            auth_method(true, Some("none"), &post_only),
            ClientSecretPost
        );
        assert_eq!(
            auth_method(true, None, &methods(&["private_key_jwt"])),
            ClientSecretBasic
        );
    }
}
