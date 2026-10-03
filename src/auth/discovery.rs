//! Finds the authorization server for an MCP server: protected resource
//! metadata (RFC 9728), then authorization server metadata (RFC 8414 and
//! `OpenID` Connect Discovery). A server with no resource metadata at all
//! gets the 2025-03-26 legacy profile.

use reqwest::StatusCode;
use serde::Deserialize;
use url::Url;

use crate::auth::http::{Answer, AuthHttp};
use crate::error::{Error, ErrorKind};
use crate::http::url_policy::UrlPolicy;
use crate::store::record::is_scope;

/// Most authorization servers or scopes read from one metadata document.
const MAX_LIST: usize = 64;

/// The authorization server's endpoints and what it supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthServer {
    /// The issuer, as a URL.
    pub(crate) issuer: Url,
    /// The issuer exactly as the metadata spelled it, for the `iss` check.
    pub(crate) issuer_text: String,
    /// Whether the callback must carry `iss`.
    pub(crate) iss_required: bool,
    pub(crate) authorization_endpoint: Url,
    pub(crate) token_endpoint: Url,
    pub(crate) registration_endpoint: Option<Url>,
    /// `token_endpoint_auth_methods_supported`.
    pub(crate) auth_methods: Vec<String>,
    /// `client_id_metadata_document_supported`.
    pub(crate) cimd: bool,
}

/// What discovery found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Discovered {
    /// The protected resource: sent as `resource` and stored with the tokens.
    pub(crate) resource: Url,
    /// `scopes_supported` from the resource metadata.
    pub(crate) scopes_supported: Vec<String>,
    pub(crate) server: AuthServer,
}

#[derive(Debug, Deserialize)]
struct ResourceMetadata {
    resource: String,
    #[serde(default)]
    authorization_servers: Vec<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: Option<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    authorization_response_iss_parameter_supported: Option<bool>,
    client_id_metadata_document_supported: Option<bool>,
}

/// Discovers the authorization server for `server`. `hint` is the
/// challenge's `resource_metadata` URL.
///
/// # Errors
/// `url_rejected`, `resource_mismatch`, `http_status`, `protocol_error`,
/// `unsupported_feature` (no S256), and the network errors.
pub(crate) async fn discover(
    http: &AuthHttp,
    server: &Url,
    hint: Option<&Url>,
) -> Result<Discovered, Error> {
    let policy = UrlPolicy::new(server.clone());
    let mut candidates = Vec::with_capacity(3);
    if let Some(hint) = hint {
        policy.check("resource metadata URL", hint)?;
        candidates.push(hint.clone());
    }
    candidates.extend(
        well_known(server, "oauth-protected-resource")
            .into_iter()
            .filter(|candidate| Some(candidate) != hint),
    );
    for candidate in &candidates {
        if let Some(answer) = fetch(http, candidate, "resource metadata").await? {
            let metadata: ResourceMetadata = answer.json("resource metadata")?;
            return modern(http, &policy, server, metadata).await;
        }
    }
    legacy(http, &policy, server).await
}

/// The RFC 9728 URLs for `server`: path-specific first, then the root.
fn well_known(server: &Url, suffix: &str) -> Vec<Url> {
    let path = server.path().trim_end_matches('/');
    let root = at_path(server, &format!("/.well-known/{suffix}"));
    if path.is_empty() {
        vec![root]
    } else {
        vec![
            at_path(server, &format!("/.well-known/{suffix}{path}")),
            root,
        ]
    }
}

/// GETs `url`. `None` on 404; any other status but 200 is an error.
async fn fetch(http: &AuthHttp, url: &Url, what: &str) -> Result<Option<Answer>, Error> {
    let answer = http.send(http.get(url)).await?;
    match answer.status {
        StatusCode::OK => Ok(Some(answer)),
        StatusCode::NOT_FOUND => Ok(None),
        _ => Err(answer.unexpected(what)),
    }
}

async fn modern(
    http: &AuthHttp,
    policy: &UrlPolicy,
    server: &Url,
    metadata: ResourceMetadata,
) -> Result<Discovered, Error> {
    let resource = parse_url(&metadata.resource, "resource")?;
    if !resource_matches(&resource, server) {
        return Err(Error::new(
            ErrorKind::ResourceMismatch,
            format!(
                "the resource metadata names {} as its resource, which does not cover {}",
                resource.origin().ascii_serialization(),
                server.origin().ascii_serialization()
            ),
        ));
    }
    let issuer = match metadata.authorization_servers.as_slice() {
        [first, ..] if metadata.authorization_servers.len() <= MAX_LIST => {
            parse_url(first, "authorization server")?
        }
        _ => {
            return Err(protocol(
                "the resource metadata lists no usable authorization server",
            ));
        }
    };
    policy.check("authorization server", &issuer)?;
    let scopes = scopes(metadata.scopes_supported)?;
    let server = auth_server(http, policy, &issuer).await?;
    Ok(Discovered {
        resource,
        scopes_supported: scopes,
        server,
    })
}

/// Whether `resource` covers `server`: the same origin, and a path equal
/// to the server's or a prefix of it ending on a segment boundary.
pub(crate) fn resource_matches(resource: &Url, server: &Url) -> bool {
    let prefix = resource.path().trim_end_matches('/');
    let path = server.path().trim_end_matches('/');
    resource.origin() == server.origin()
        && resource.query().is_none()
        && resource.fragment().is_none()
        && path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Fetches and checks the metadata of `issuer`, trying the URLs in the
/// order of the MCP specification.
async fn auth_server(
    http: &AuthHttp,
    policy: &UrlPolicy,
    issuer: &Url,
) -> Result<AuthServer, Error> {
    for candidate in server_metadata_urls(issuer) {
        if let Some(answer) = fetch(http, &candidate, "authorization server metadata").await? {
            let metadata: ServerMetadata = answer.json("authorization server metadata")?;
            return checked(policy, issuer, metadata);
        }
    }
    Err(Error::new(
        ErrorKind::HttpStatus,
        format!(
            "{} has no authorization server metadata",
            issuer.origin().ascii_serialization()
        ),
    ))
}

fn server_metadata_urls(issuer: &Url) -> Vec<Url> {
    let path = issuer.path().trim_end_matches('/');
    if path.is_empty() {
        return vec![
            at_path(issuer, "/.well-known/oauth-authorization-server"),
            at_path(issuer, "/.well-known/openid-configuration"),
        ];
    }
    vec![
        at_path(
            issuer,
            &format!("/.well-known/oauth-authorization-server{path}"),
        ),
        at_path(issuer, &format!("/.well-known/openid-configuration{path}")),
        at_path(issuer, &format!("{path}/.well-known/openid-configuration")),
    ]
}

fn checked(
    policy: &UrlPolicy,
    issuer: &Url,
    metadata: ServerMetadata,
) -> Result<AuthServer, Error> {
    if parse_url(&metadata.issuer, "issuer")? != *issuer {
        return Err(protocol(
            "the authorization server metadata names another issuer",
        ));
    }
    if !metadata
        .code_challenge_methods_supported
        .iter()
        .any(|method| method == "S256")
    {
        return Err(Error::new(
            ErrorKind::UnsupportedFeature,
            "the authorization server does not support PKCE with S256",
        ));
    }
    let endpoint = |raw: &str, role: &str| {
        parse_url(raw, role).and_then(|url| policy.check(role, &url).map(|()| url))
    };
    let registration_endpoint = metadata
        .registration_endpoint
        .as_deref()
        .map(|raw| endpoint(raw, "registration endpoint"))
        .transpose()?;
    let auth_methods = metadata
        .token_endpoint_auth_methods_supported
        .unwrap_or_else(|| vec!["client_secret_basic".to_owned()]);
    Ok(AuthServer {
        issuer: issuer.clone(),
        issuer_text: metadata.issuer,
        iss_required: metadata.authorization_response_iss_parameter_supported == Some(true),
        authorization_endpoint: endpoint(
            &metadata.authorization_endpoint,
            "authorization endpoint",
        )?,
        token_endpoint: endpoint(&metadata.token_endpoint, "token endpoint")?,
        registration_endpoint,
        auth_methods: auth_methods.into_iter().take(MAX_LIST).collect(),
        cimd: metadata.client_id_metadata_document_supported == Some(true),
    })
}

/// The 2025-03-26 profile: metadata at the server's origin root if there
/// is any, else the default endpoints there.
async fn legacy(http: &AuthHttp, policy: &UrlPolicy, server: &Url) -> Result<Discovered, Error> {
    let issuer = at_path(server, "/");
    let root = at_path(server, "/.well-known/oauth-authorization-server");
    let found = match fetch(http, &root, "authorization server metadata").await? {
        Some(answer) => checked(
            policy,
            &issuer,
            answer.json("authorization server metadata")?,
        )?,
        None => AuthServer {
            issuer_text: issuer.origin().ascii_serialization(),
            iss_required: false,
            authorization_endpoint: at_path(server, "/authorize"),
            token_endpoint: at_path(server, "/token"),
            registration_endpoint: Some(at_path(server, "/register")),
            auth_methods: vec!["client_secret_basic".to_owned()],
            cimd: false,
            issuer,
        },
    };
    Ok(Discovered {
        resource: server.clone(),
        scopes_supported: Vec::new(),
        server: found,
    })
}

fn scopes(scopes: Vec<String>) -> Result<Vec<String>, Error> {
    if scopes.len() > MAX_LIST || !scopes.iter().all(|scope| is_scope(scope)) {
        return Err(protocol("the resource metadata lists malformed scopes"));
    }
    Ok(scopes)
}

/// `base` with its path replaced and no query or fragment.
fn at_path(base: &Url, path: &str) -> Url {
    let mut url = base.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

fn parse_url(raw: &str, role: &str) -> Result<Url, Error> {
    Url::parse(raw).map_err(|_| protocol(&format!("the {role} is not a valid URL")))
}

fn protocol(message: &str) -> Error {
    Error::new(ErrorKind::ProtocolError, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> Url {
        Url::parse(raw).unwrap()
    }

    #[test]
    fn a_resource_covers_its_own_path_and_paths_below() {
        let server = url("https://service.example/resources/client");
        for resource in [
            "https://service.example/resources/client",
            "https://service.example/resources/client/",
            "https://service.example/resources",
            "https://service.example",
            "https://service.example/",
        ] {
            assert!(resource_matches(&url(resource), &server), "{resource}");
        }
        assert!(resource_matches(
            &url("https://a.example/mcp"),
            &url("https://a.example/mcp/")
        ));
    }

    #[test]
    fn a_resource_that_does_not_cover_the_server_is_rejected() {
        let server = url("https://service.example/resources/client");
        for resource in [
            "https://service.example/mcp",
            "https://service.example/resources/cli",
            "https://other.example/resources/client",
            "http://service.example/resources/client",
            "https://service.example/resources/client?x=1",
            "https://service.example/resources/client#x",
        ] {
            assert!(!resource_matches(&url(resource), &server), "{resource}");
        }
        assert!(!resource_matches(
            &url("https://a.example/mc"),
            &url("https://a.example/mcp")
        ));
    }

    #[test]
    fn metadata_urls_follow_the_specification_order() {
        let paths = |urls: Vec<Url>| urls.iter().map(|u| u.path().to_owned()).collect::<Vec<_>>();
        assert_eq!(
            paths(well_known(
                &url("https://a.example/mcp?x=1"),
                "oauth-protected-resource"
            )),
            [
                "/.well-known/oauth-protected-resource/mcp",
                "/.well-known/oauth-protected-resource"
            ]
        );
        assert_eq!(
            paths(well_known(
                &url("https://a.example/"),
                "oauth-protected-resource"
            )),
            ["/.well-known/oauth-protected-resource"]
        );
        assert_eq!(
            paths(server_metadata_urls(&url("https://a.example/tenant/"))),
            [
                "/.well-known/oauth-authorization-server/tenant",
                "/.well-known/openid-configuration/tenant",
                "/tenant/.well-known/openid-configuration"
            ]
        );
        assert_eq!(
            paths(server_metadata_urls(&url("https://a.example"))),
            [
                "/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration"
            ]
        );
    }
}
