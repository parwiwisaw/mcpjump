//! A scripted OAuth authorization server, on a thread of its own so an
//! in-process CLI run can block on its own runtime. It serves resource and
//! server metadata, `/authorize` answering at once with a redirect,
//! `/token` with rotating refresh tokens, `/register`, a client metadata
//! document, and `/mcp`, which refuses every request with a Bearer
//! challenge unless the script has it serve a tool-less MCP server.
//! It records every request it answers. The end-to-end tests include this
//! file too, so it uses no other test support.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::{Url, form_urlencoded};

/// How `/register` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Registration {
    /// Registers public clients.
    Public,
    /// Registers public clients, answering 200 rather than 201.
    PublicOk,
    /// Refuses public clients as `invalid_client_metadata`, then registers
    /// a `client_secret_basic` client.
    SecretOnly,
    /// Refuses every registration.
    Refuse,
    /// Advertises no registration endpoint.
    Absent,
    /// Answers every registration with a 500.
    Fail,
    /// Answers every registration with a body that is not an object.
    Garbage,
    /// Registers a client with an empty `client_id`.
    Unusable,
    /// Like `SecretOnly`, but answers the secret registration only after
    /// [`SLOW_SECS`].
    SlowSecret,
}

/// How long a `SlowSecret` registration takes.
const SLOW_SECS: u64 = 3;

/// What the authorization response says about its issuer (RFC 9207).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Iss {
    /// Advertised, and sent right.
    Right,
    /// Neither advertised nor sent.
    Unadvertised,
    /// Advertised, but not sent.
    Omitted,
    /// Advertised, and sent naming another server.
    Wrong,
}

/// How a metadata document is served.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Doc {
    /// As built, after the function changes it.
    Patched(fn(&mut Value)),
    /// With this status and no body.
    Status(u16),
}

/// How the server behaves.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Script {
    pub(crate) registration: Registration,
    pub(crate) iss: Iss,
    /// `/authorize` answers `access_denied`.
    pub(crate) deny: bool,
    /// Advertises Client ID Metadata Document support.
    pub(crate) cimd: bool,
    /// The `redirect_uris` of the client metadata document.
    pub(crate) redirect_uris: Vec<String>,
    /// The `client_id` the document names; `None` names its own URL.
    pub(crate) document_client_id: Option<String>,
    pub(crate) expires_in: Option<u64>,
    /// Issues refresh tokens.
    pub(crate) refresh_tokens: bool,
    /// Refuses every refresh as `invalid_grant`.
    pub(crate) refuse_refresh: bool,
    /// The `scope` of token responses.
    pub(crate) scope: Option<String>,
    /// The protected resource metadata.
    pub(crate) resource_doc: Doc,
    /// The authorization server metadata.
    pub(crate) metadata_doc: Doc,
    /// Issues tokens of about [`LONG_TOKEN`] bytes each.
    pub(crate) long_tokens: bool,
    /// `/mcp` serves an MCP server with no tools to any access token it
    /// issued.
    pub(crate) serve_mcp: bool,
}

/// The length of a long token: two fit a token response, not one record.
const LONG_TOKEN: usize = 16_000;

impl Default for Script {
    fn default() -> Self {
        Self {
            registration: Registration::Public,
            iss: Iss::Right,
            deny: false,
            cimd: false,
            redirect_uris: Vec::new(),
            document_client_id: None,
            expires_in: Some(3600),
            refresh_tokens: true,
            refuse_refresh: false,
            scope: Some("read".to_owned()),
            resource_doc: Doc::Patched(|_| {}),
            metadata_doc: Doc::Patched(|_| {}),
            long_tokens: false,
            serve_mcp: false,
        }
    }
}

/// One request the server answered.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    pub(crate) path: String,
    /// The query, form or JSON body's string fields.
    pub(crate) params: BTreeMap<String, String>,
    pub(crate) authorization: Option<String>,
}

#[derive(Debug)]
struct Inner {
    script: Script,
    base: Url,
    requests: Vec<Request>,
    issued: u32,
    refresh_token: Option<String>,
    code_challenge: Option<String>,
}

type Shared = Arc<Mutex<Inner>>;

/// A running server.
#[derive(Debug)]
pub(crate) struct OAuthServer {
    pub(crate) base: Url,
    inner: Shared,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    complete: mpsc::Receiver<()>,
    worker: Option<thread::JoinHandle<()>>,
}

impl OAuthServer {
    /// Starts a server following `script` on a fresh loopback port.
    pub(crate) fn start(script: Script) -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let (completed, complete) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let base = Url::parse(&format!("http://{address}/")).unwrap();
                let inner = Arc::new(Mutex::new(Inner {
                    script,
                    base: base.clone(),
                    requests: Vec::new(),
                    issued: 0,
                    refresh_token: None,
                    code_challenge: None,
                }));
                sender.send((base, Arc::clone(&inner))).unwrap();
                tokio::select! {
                    result = axum::serve(listener, router(inner)) => result.unwrap(),
                    result = stopped => result.unwrap(),
                }
            });
            completed.send(()).unwrap();
        });
        let (base, inner) = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            base,
            inner,
            shutdown: Some(shutdown),
            complete,
            worker: Some(worker),
        }
    }

    /// The MCP endpoint the server protects.
    pub(crate) fn mcp_url(&self) -> Url {
        self.base.join("mcp").unwrap()
    }

    /// The resource metadata URL a challenge names.
    pub(crate) fn resource_metadata(&self) -> Url {
        self.base
            .join(".well-known/oauth-protected-resource/mcp")
            .unwrap()
    }

    /// Makes `token` the refresh token the server accepts.
    pub(crate) fn expect_refresh(&self, token: &str) {
        self.inner.lock().unwrap().refresh_token = Some(token.to_owned());
    }

    /// Every request so far.
    pub(crate) fn requests(&self) -> Vec<Request> {
        self.inner.lock().unwrap().requests.clone()
    }

    /// The paths of every request so far.
    pub(crate) fn paths(&self) -> Vec<String> {
        self.requests().into_iter().map(|r| r.path).collect()
    }

    /// The requests to `path`.
    pub(crate) fn to(&self, path: &str) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(|request| request.path == path)
            .collect()
    }
}

impl Drop for OAuthServer {
    fn drop(&mut self) {
        let requested = self
            .shutdown
            .take()
            .is_some_and(|shutdown| shutdown.send(()).is_ok());
        if matches!(
            self.complete.recv_timeout(Duration::from_secs(5)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            assert!(
                thread::panicking(),
                "OAuth fixture did not stop in 5 seconds"
            );
            return;
        }
        let joined = self
            .worker
            .take()
            .is_some_and(|worker| worker.join().is_ok());
        assert!(
            joined || thread::panicking(),
            "OAuth fixture worker failed; shutdown requested: {requested}"
        );
    }
}

fn router(inner: Shared) -> Router {
    Router::new()
        .route("/.well-known/oauth-protected-resource/mcp", get(resource))
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/register", post(register))
        .route("/client.json", get(client_document))
        .route("/mcp", any(mcp))
        .with_state(inner)
}

fn pairs(text: &str) -> BTreeMap<String, String> {
    form_urlencoded::parse(text.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn record(inner: &mut Inner, path: &str, params: BTreeMap<String, String>, headers: &HeaderMap) {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .map(|value| value.to_str().unwrap().to_owned());
    inner.requests.push(Request {
        path: path.to_owned(),
        params,
        authorization,
    });
}

fn json_answer(status: StatusCode, value: &Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        value.to_string(),
    )
        .into_response()
}

fn oauth_error(code: &str) -> Response {
    json_answer(StatusCode::BAD_REQUEST, &json!({ "error": code }))
}

async fn resource(State(inner): State<Shared>, headers: HeaderMap) -> Response {
    let mut inner = inner.lock().unwrap();
    record(&mut inner, "/prm", BTreeMap::new(), &headers);
    let base = inner.base.clone();
    let document = json!({
        "resource": base.join("mcp").unwrap().as_str(),
        "authorization_servers": [base.as_str().trim_end_matches('/')],
        "scopes_supported": ["read"],
    });
    serve(inner.script.resource_doc, document)
}

fn serve(doc: Doc, mut document: Value) -> Response {
    match doc {
        Doc::Patched(patch) => {
            patch(&mut document);
            json_answer(StatusCode::OK, &document)
        }
        Doc::Status(status) => StatusCode::from_u16(status).unwrap().into_response(),
    }
}

async fn metadata(State(inner): State<Shared>, headers: HeaderMap) -> Response {
    let mut inner = inner.lock().unwrap();
    record(&mut inner, "/metadata", BTreeMap::new(), &headers);
    let (base, script) = (&inner.base, &inner.script);
    let methods = match script.registration {
        Registration::SecretOnly | Registration::SlowSecret => json!(["client_secret_basic"]),
        _ => json!(["none", "client_secret_basic"]),
    };
    let mut metadata = json!({
        "issuer": base.as_str().trim_end_matches('/'),
        "authorization_endpoint": base.join("authorize").unwrap().as_str(),
        "token_endpoint": base.join("token").unwrap().as_str(),
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": methods,
        "authorization_response_iss_parameter_supported": script.iss != Iss::Unadvertised,
        "client_id_metadata_document_supported": script.cimd,
    });
    if script.registration != Registration::Absent {
        metadata["registration_endpoint"] = json!(base.join("register").unwrap().as_str());
    }
    serve(script.metadata_doc, metadata)
}

async fn authorize(State(inner): State<Shared>, headers: HeaderMap, uri: Uri) -> Response {
    let params = pairs(uri.query().unwrap_or_default());
    let mut inner = inner.lock().unwrap();
    record(&mut inner, "/authorize", params.clone(), &headers);
    inner.code_challenge = params.get("code_challenge").cloned();
    let issuer = inner.base.as_str().trim_end_matches('/').to_owned();
    let mut target = Url::parse(&params["redirect_uri"]).unwrap();
    {
        let mut query = target.query_pairs_mut();
        query.append_pair("state", &params["state"]);
        if inner.script.deny {
            query.append_pair("error", "access_denied");
        } else {
            query.append_pair("code", "code-1");
            match inner.script.iss {
                Iss::Right => {
                    query.append_pair("iss", &issuer);
                }
                Iss::Wrong => {
                    query.append_pair("iss", "http://127.0.0.1:1");
                }
                Iss::Unadvertised | Iss::Omitted => {}
            }
        }
    }
    (StatusCode::FOUND, [(header::LOCATION, target.to_string())]).into_response()
}

async fn register(State(inner): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let sent: Value = serde_json::from_slice(&body).unwrap();
    let method = sent["token_endpoint_auth_method"]
        .as_str()
        .unwrap()
        .to_owned();
    let params = BTreeMap::from([
        ("token_endpoint_auth_method".to_owned(), method.clone()),
        (
            "redirect_uri".to_owned(),
            sent["redirect_uris"][0].as_str().unwrap().to_owned(),
        ),
        (
            "application_type".to_owned(),
            sent["application_type"].as_str().unwrap().to_owned(),
        ),
    ]);
    let registration = {
        let mut inner = inner.lock().unwrap();
        record(&mut inner, "/register", params, &headers);
        inner.script.registration
    };
    let secret = json!({
        "client_id": "secret-client",
        "client_secret": "s3cret",
        "token_endpoint_auth_method": "client_secret_basic",
    });
    match (registration, method.as_str()) {
        (Registration::Refuse, _) => oauth_error("invalid_redirect_uri"),
        (Registration::SecretOnly | Registration::SlowSecret, "none") => {
            oauth_error("invalid_client_metadata")
        }
        (Registration::SecretOnly, _) => json_answer(StatusCode::CREATED, &secret),
        (Registration::SlowSecret, _) => {
            tokio::time::sleep(Duration::from_secs(SLOW_SECS)).await;
            json_answer(StatusCode::CREATED, &secret)
        }
        (Registration::Fail, _) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        (Registration::Garbage, _) => json_answer(StatusCode::CREATED, &json!("x")),
        (Registration::PublicOk, _) => {
            json_answer(StatusCode::OK, &json!({ "client_id": "public-client" }))
        }
        (Registration::Unusable, _) => {
            json_answer(StatusCode::CREATED, &json!({ "client_id": "" }))
        }
        _ => json_answer(
            StatusCode::CREATED,
            &json!({ "client_id": "public-client" }),
        ),
    }
}

async fn token(State(inner): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let params = pairs(&String::from_utf8_lossy(&body));
    let mut inner = inner.lock().unwrap();
    record(&mut inner, "/token", params.clone(), &headers);
    let param = |name: &str| params.get(name).map(String::as_str);
    let valid = match param("grant_type") {
        Some("authorization_code") => {
            let verifier = param("code_verifier").unwrap_or_default();
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            param("code") == Some("code-1")
                && inner.code_challenge.as_deref() == Some(challenge.as_str())
        }
        Some("refresh_token") => {
            !inner.script.refuse_refresh && param("refresh_token") == inner.refresh_token.as_deref()
        }
        _ => false,
    };
    if !valid {
        return oauth_error("invalid_grant");
    }
    inner.issued += 1;
    let issued = inner.issued;
    let padding = if inner.script.long_tokens {
        "x".repeat(LONG_TOKEN)
    } else {
        String::new()
    };
    let mut answer = json!({
        "access_token": format!("at-{issued}{padding}"),
        "token_type": "Bearer",
    });
    if let Some(expires_in) = inner.script.expires_in {
        answer["expires_in"] = json!(expires_in);
    }
    if inner.script.refresh_tokens {
        let refresh_token = format!("rt-{issued}{padding}");
        answer["refresh_token"] = json!(refresh_token);
        inner.refresh_token = Some(refresh_token);
    }
    if let Some(scope) = &inner.script.scope {
        answer["scope"] = json!(scope);
    }
    json_answer(StatusCode::OK, &answer)
}

async fn client_document(State(inner): State<Shared>, headers: HeaderMap) -> Response {
    let mut inner = inner.lock().unwrap();
    record(&mut inner, "/client.json", BTreeMap::new(), &headers);
    let own = inner.base.join("client.json").unwrap().to_string();
    let client_id = inner.script.document_client_id.clone().unwrap_or(own);
    json_answer(
        StatusCode::OK,
        &json!({ "client_id": client_id, "redirect_uris": inner.script.redirect_uris }),
    )
}

async fn mcp(State(inner): State<Shared>, headers: HeaderMap, body: Bytes) -> Response {
    let mut inner = inner.lock().unwrap();
    record(&mut inner, "/mcp", BTreeMap::new(), &headers);
    if inner.script.serve_mcp && issued_bearer(&inner, &headers) {
        return mcp_answer(&body);
    }
    let metadata = inner
        .base
        .join(".well-known/oauth-protected-resource/mcp")
        .unwrap();
    let challenge = format!("Bearer resource_metadata=\"{metadata}\"");
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, challenge)],
    )
        .into_response()
}

/// Whether the request carries an access token this server issued.
fn issued_bearer(inner: &Inner, headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer at-"))
        .and_then(|number| number.parse::<u32>().ok())
        .is_some_and(|number| (1..=inner.issued).contains(&number))
}

/// A JSON-RPC answer from an MCP server that has no tools and no stream.
fn mcp_answer(body: &[u8]) -> Response {
    let Ok(message) = serde_json::from_slice::<Value>(body) else {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    };
    let Some(id) = message.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let result = match message["method"].as_str() {
        Some("initialize") => json!({
            "protocolVersion": message["params"]["protocolVersion"],
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "fixture", "version": "1.0.0" },
        }),
        Some("tools/list") => json!({ "tools": [] }),
        _ => {
            let error = json!({ "code": -32601, "message": "method not found" });
            let answer = json!({ "jsonrpc": "2.0", "id": id, "error": error });
            return json_answer(StatusCode::OK, &answer);
        }
    };
    json_answer(
        StatusCode::OK,
        &json!({ "jsonrpc": "2.0", "id": id, "result": result }),
    )
}
