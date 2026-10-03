//! The records mcpjump stores per server, as JSON. A record read back is
//! checked field by field: a store is only as trustworthy as the disk or
//! keyring under it.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::model::check_client_id;
use crate::config::validate;
use crate::error::Error;
use crate::store::{self, Key};

/// Longest token or secret accepted.
const MAX_SECRET_LEN: usize = 16 * 1024;

/// Most scopes one token may carry.
const MAX_SCOPES: usize = 64;

/// Longest scope accepted.
const MAX_SCOPE_LEN: usize = 256;

/// Most bytes of pending scopes, joined by spaces.
pub const MAX_PENDING_SCOPE_BYTES: usize = 1024;

/// A record type with its read-back check.
pub trait Record: Serialize + DeserializeOwned {
    /// Whether every field holds a value mcpjump could have written.
    fn is_valid(&self) -> bool;
}

/// Tokens from the authorization server, with what they were issued for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRecord {
    /// The access token.
    pub access_token: String,
    /// The refresh token, if one was issued.
    pub refresh_token: Option<String>,
    /// When the access token expires, in seconds since the Unix epoch.
    pub expires_at: Option<u64>,
    /// The token type; only `Bearer` is used.
    pub token_type: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// The authorization server that issued the tokens.
    pub issuer: Url,
    /// The protected resource the tokens are for.
    pub resource: Url,
    /// The client the tokens were issued to.
    pub client_id: String,
    /// Where to refresh them.
    pub token_endpoint: Url,
    /// Scopes a server asked for in a 403 since the last login; the next
    /// login requests them too.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_scopes: Vec<String>,
}

impl Record for TokenRecord {
    fn is_valid(&self) -> bool {
        is_secret(&self.access_token)
            && self.refresh_token.as_deref().is_none_or(is_secret)
            && self.token_type.eq_ignore_ascii_case("bearer")
            && self.scopes.len() <= MAX_SCOPES
            && self.scopes.iter().all(|scope| is_scope(scope))
            && check_client_id(&self.client_id).is_ok()
            && is_secure(&self.issuer)
            && is_secure(&self.resource)
            && is_secure(&self.token_endpoint)
            && self.pending_scopes.iter().all(|scope| is_scope(scope))
            && self.pending_scopes.join(" ").len() <= MAX_PENDING_SCOPE_BYTES
    }
}

/// How a client authenticates at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuth {
    /// A public client: no secret.
    None,
    /// The secret in HTTP Basic auth.
    ClientSecretBasic,
    /// The secret in the request body.
    ClientSecretPost,
}

/// How the client came to be registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMethod {
    /// A client ID the user configured.
    Preregistered,
    /// A Client ID Metadata Document URL.
    MetadataDocument,
    /// Dynamic Client Registration.
    Dynamic,
}

/// The OAuth client mcpjump uses with one authorization server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRecord {
    /// The authorization server.
    pub issuer: Url,
    /// The client ID.
    pub client_id: String,
    /// The client secret, for a confidential client.
    pub client_secret: Option<String>,
    /// How the client authenticates at the token endpoint.
    pub token_endpoint_auth_method: TokenEndpointAuth,
    /// The loopback redirect URI registered for the client.
    pub redirect_uri: Url,
    /// How the client was registered.
    pub method: RegistrationMethod,
}

impl Record for RegistrationRecord {
    fn is_valid(&self) -> bool {
        let needs_secret = self.token_endpoint_auth_method != TokenEndpointAuth::None;
        check_client_id(&self.client_id).is_ok()
            && self.client_secret.as_deref().is_none_or(is_secret)
            && self.client_secret.is_some() == needs_secret
            && is_secure(&self.issuer)
            && is_redirect(&self.redirect_uri)
    }
}

/// The JSON text of `record`. Serializing these plain structs cannot fail;
/// if it ever did, the empty result is rejected by every store's check.
#[must_use]
pub fn encode<R: Record>(record: &R) -> Vec<u8> {
    serde_json::to_vec(record).unwrap_or_default()
}

/// Parses and checks a record read from the store for `key`.
///
/// # Errors
/// `credential_invalid` if it does not parse or fails the check.
pub fn decode<R: Record>(key: &Key, bytes: &[u8]) -> Result<R, Error> {
    serde_json::from_slice::<R>(bytes)
        .ok()
        .filter(R::is_valid)
        .ok_or_else(|| store::corrupt(key))
}

/// A token or secret: 1 to [`MAX_SECRET_LEN`] visible ASCII characters.
pub(crate) fn is_secret(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SECRET_LEN
        && value.bytes().all(|b| b.is_ascii_graphic())
}

/// An authorization server or resource: HTTPS, or HTTP on loopback.
pub(crate) fn is_secure(url: &Url) -> bool {
    url.scheme() == "https" || (url.scheme() == "http" && validate::is_loopback(url))
}

/// The loopback callback mcpjump listens on: `http://127.0.0.1:<port>/callback`.
pub(crate) fn is_redirect(url: &Url) -> bool {
    url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port().is_some()
        && url.path() == "/callback"
        && url.query().is_none()
        && url.fragment().is_none()
}

/// A scope token (RFC 6749 section 3.3): visible ASCII other than `"` and `\`.
pub(crate) fn is_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= MAX_SCOPE_LEN
        && scope
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}
