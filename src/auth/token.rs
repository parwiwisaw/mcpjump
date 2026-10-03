//! Token endpoint requests: the authorization code exchange and the refresh
//! grant (RFC 6749 sections 4.1.3 and 6), each with `resource` (RFC 8707).
//! Client authentication goes only to the validated token endpoint.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use url::form_urlencoded;

use crate::auth::challenge::is_error_code;
use crate::auth::http::{Answer, AuthHttp};
use crate::error::{Error, ErrorKind};
use crate::store::record::{
    RegistrationRecord, TokenEndpointAuth, TokenRecord, is_scope, is_secret,
};

/// Longest `expires_in` accepted: ten years.
const MAX_EXPIRES_IN: u64 = 315_360_000;

/// Most scopes one token response may grant.
const MAX_SCOPES: usize = 64;

/// The grant being redeemed.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Grant<'a> {
    /// An authorization code from the callback.
    Code {
        code: &'a str,
        verifier: &'a str,
        redirect_uri: &'a str,
    },
    /// The stored refresh token.
    Refresh { refresh_token: &'a str },
}

/// What a token is bound to, copied into every record it lands in.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Binding<'a> {
    pub(crate) client: &'a RegistrationRecord,
    pub(crate) resource: &'a url::Url,
    pub(crate) token_endpoint: &'a url::Url,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

/// Redeems `grant` and returns the record to store. `previous` supplies
/// the refresh token and scopes a refresh response leaves out; `requested`
/// the scopes an exchange response leaves out.
///
/// # Errors
/// `auth_required` when the server refuses the grant, `protocol_error` for
/// a response mcpjump cannot use, and the HTTP errors.
pub(crate) async fn redeem(
    http: &AuthHttp,
    binding: Binding<'_>,
    grant: Grant<'_>,
    previous: Option<&TokenRecord>,
    requested: &[String],
    now: u64,
) -> Result<TokenRecord, Error> {
    let answer = http.send(request(http, binding, grant)).await?;
    let response = accepted(&answer)?;
    let fallback = previous.map_or(requested, |previous| previous.scopes.as_slice());
    let scopes = granted(response.scope.as_deref(), fallback)?;
    let refresh_token = response
        .refresh_token
        .or_else(|| previous.and_then(|previous| previous.refresh_token.clone()));
    let record = TokenRecord {
        access_token: response.access_token,
        refresh_token,
        expires_at: expiry(response.expires_in, now)?,
        token_type: response.token_type,
        scopes,
        issuer: binding.client.issuer.clone(),
        resource: binding.resource.clone(),
        client_id: binding.client.client_id.clone(),
        token_endpoint: binding.token_endpoint.clone(),
        pending_scopes: previous
            .map(|p| p.pending_scopes.clone())
            .unwrap_or_default(),
    };
    checked(record)
}

fn request(http: &AuthHttp, binding: Binding<'_>, grant: Grant<'_>) -> reqwest::RequestBuilder {
    let client = binding.client;
    let mut form = form_urlencoded::Serializer::new(String::new());
    match grant {
        Grant::Code {
            code,
            verifier,
            redirect_uri,
        } => form
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("code_verifier", verifier)
            .append_pair("redirect_uri", redirect_uri),
        Grant::Refresh { refresh_token } => form
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", refresh_token),
    };
    form.append_pair("resource", binding.resource.as_str());
    let secret = client.client_secret.as_deref().unwrap_or_default();
    let builder = http
        .post(binding.token_endpoint)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    match client.token_endpoint_auth_method {
        TokenEndpointAuth::None => {
            form.append_pair("client_id", &client.client_id);
            builder
        }
        TokenEndpointAuth::ClientSecretPost => {
            form.append_pair("client_id", &client.client_id);
            form.append_pair("client_secret", secret);
            builder
        }
        TokenEndpointAuth::ClientSecretBasic => {
            builder.header(AUTHORIZATION, basic(&client.client_id, secret))
        }
    }
    .body(form.finish())
}

/// HTTP Basic credentials, each part form-urlencoded first (RFC 6749
/// section 2.3.1).
fn basic(client_id: &str, secret: &str) -> String {
    let encode = |part: &str| form_urlencoded::byte_serialize(part.as_bytes()).collect::<String>();
    let pair = format!("{}:{}", encode(client_id), encode(secret));
    format!("Basic {}", STANDARD.encode(pair))
}

/// The token response of a 200, or the error for any other answer.
fn accepted(answer: &Answer) -> Result<TokenResponse, Error> {
    match answer.status {
        StatusCode::OK => answer.json("token response"),
        StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED => {
            Err(refused(answer, "the token request"))
        }
        _ => Err(answer.unexpected("the token request")),
    }
}

/// `auth_required` naming the OAuth error code an authorization server
/// sent for `what`. The code is shown only if it is well formed.
pub(crate) fn refused(answer: &Answer, what: &str) -> Error {
    let code = answer
        .json::<ErrorResponse>("error response")
        .ok()
        .map(|response| response.error)
        .filter(|code| is_error_code(code))
        .unwrap_or_else(|| "unknown".to_owned());
    Error::new(
        ErrorKind::AuthRequired,
        format!("{} refused {what}: {code:?}", answer.origin),
    )
}

fn granted(scope: Option<&str>, fallback: &[String]) -> Result<Vec<String>, Error> {
    let Some(scope) = scope else {
        return Ok(fallback.to_vec());
    };
    let scopes: Vec<String> = scope
        .split(' ')
        .filter(|scope| !scope.is_empty())
        .take(MAX_SCOPES + 1)
        .map(str::to_owned)
        .collect();
    if scopes.len() > MAX_SCOPES || !scopes.iter().all(|scope| is_scope(scope)) {
        return Err(unusable("its scope"));
    }
    Ok(scopes)
}

fn expiry(expires_in: Option<u64>, now: u64) -> Result<Option<u64>, Error> {
    expires_in
        .map(|seconds| {
            (1..=MAX_EXPIRES_IN)
                .contains(&seconds)
                .then(|| now.checked_add(seconds))
                .flatten()
                .ok_or_else(|| unusable("its expires_in"))
        })
        .transpose()
}

fn checked(record: TokenRecord) -> Result<TokenRecord, Error> {
    if !record.token_type.eq_ignore_ascii_case("bearer") {
        return Err(Error::new(
            ErrorKind::UnsupportedFeature,
            "the authorization server issued a token that is not a Bearer token",
        ));
    }
    if !is_secret(&record.access_token) || !record.refresh_token.as_deref().is_none_or(is_secret) {
        return Err(unusable("its tokens"));
    }
    Ok(record)
}

fn unusable(part: &str) -> Error {
    Error::new(
        ErrorKind::ProtocolError,
        format!("the token response is unusable: {part} is malformed"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_credentials_are_form_encoded_first() {
        assert_eq!(
            basic("a b", "s:t"),
            format!("Basic {}", STANDARD.encode("a+b:s%3At"))
        );
    }

    #[test]
    fn expiry_is_bounded_and_checked() {
        assert_eq!(expiry(None, 10).unwrap(), None);
        assert_eq!(expiry(Some(1), 10).unwrap(), Some(11));
        assert_eq!(
            expiry(Some(MAX_EXPIRES_IN), 0).unwrap(),
            Some(MAX_EXPIRES_IN)
        );
        for bad in [(0, 10), (MAX_EXPIRES_IN + 1, 0), (1, u64::MAX)] {
            assert_eq!(
                expiry(Some(bad.0), bad.1).unwrap_err().kind(),
                ErrorKind::ProtocolError
            );
        }
    }

    #[test]
    fn granted_scopes_fall_back_and_are_checked() {
        let fallback = vec!["a".to_owned()];
        assert_eq!(granted(None, &fallback).unwrap(), fallback);
        assert_eq!(granted(Some("x  y"), &fallback).unwrap(), ["x", "y"]);
        let many = (0..65)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        for bad in [many.as_str(), "a\"b"] {
            assert!(granted(Some(bad), &fallback).is_err());
        }
    }

    fn url(raw: &str) -> url::Url {
        url::Url::parse(raw).unwrap()
    }

    fn answer(status: u16, body: &str) -> Answer {
        Answer {
            status: StatusCode::from_u16(status).unwrap(),
            body: body.as_bytes().to_vec(),
            origin: "https://as.example".to_owned(),
        }
    }

    fn record(token_type: &str, access_token: &str, refresh_token: Option<&str>) -> TokenRecord {
        TokenRecord {
            access_token: access_token.to_owned(),
            refresh_token: refresh_token.map(str::to_owned),
            expires_at: None,
            token_type: token_type.to_owned(),
            scopes: Vec::new(),
            issuer: url("https://as.example"),
            resource: url("https://mcp.example/mcp"),
            client_id: "c".to_owned(),
            token_endpoint: url("https://as.example/token"),
            pending_scopes: Vec::new(),
        }
    }

    #[test]
    fn a_client_secret_post_client_sends_its_secret_in_the_form() {
        let http = AuthHttp::start(&crate::config::limits::Limits::default()).unwrap();
        let endpoint = url("https://as.example/token");
        let client = RegistrationRecord {
            issuer: url("https://as.example"),
            client_id: "c 1".to_owned(),
            client_secret: Some("s&t".to_owned()),
            token_endpoint_auth_method: TokenEndpointAuth::ClientSecretPost,
            redirect_uri: url("http://127.0.0.1:1/callback"),
            method: crate::store::record::RegistrationMethod::Dynamic,
        };
        let binding = Binding {
            client: &client,
            resource: &endpoint,
            token_endpoint: &endpoint,
        };
        let grant = Grant::Refresh { refresh_token: "r" };
        let built = request(&http, binding, grant).build().unwrap();
        assert!(built.headers().get(AUTHORIZATION).is_none());
        let body = built.body().unwrap().as_bytes().unwrap();
        assert_eq!(
            std::str::from_utf8(body).unwrap(),
            "grant_type=refresh_token&refresh_token=r&resource=https%3A%2F%2Fas.example%2Ftoken&client_id=c+1&client_secret=s%26t"
        );
    }

    #[test]
    fn only_a_200_is_accepted() {
        let ok = accepted(&answer(
            200,
            r#"{"access_token":"a","token_type":"Bearer"}"#,
        ));
        assert_eq!(ok.unwrap().access_token, "a");
        let failed = accepted(&answer(500, "")).unwrap_err();
        assert_eq!(failed.kind(), ErrorKind::HttpStatus);
        let refused = accepted(&answer(401, "x")).unwrap_err();
        assert_eq!(refused.kind(), ErrorKind::AuthRequired);
        assert_eq!(
            refused.message(),
            "https://as.example refused the token request: \"unknown\""
        );
    }

    #[test]
    fn only_well_formed_bearer_tokens_are_kept() {
        assert!(checked(record("bearer", "at", Some("rt"))).is_ok());
        let other = checked(record("mac", "at", None)).unwrap_err();
        assert_eq!(other.kind(), ErrorKind::UnsupportedFeature);
        for (access, refresh) in [("", None), ("a b", None), ("at", Some(""))] {
            let error = checked(record("Bearer", access, refresh)).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ProtocolError, "{access:?}");
        }
    }
}
