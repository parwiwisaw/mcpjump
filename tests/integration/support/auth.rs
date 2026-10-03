//! Helpers for the login and refresh tests: a harness pointed at an OAuth
//! fixture, refusals carrying challenges, and stored records.

use mcpjump::auth::challenge::Challenge;
use mcpjump::error::{Error, ErrorKind};
use mcpjump::store::record::{
    self, Record, RegistrationMethod, RegistrationRecord, TokenEndpointAuth, TokenRecord,
};
use mcpjump::store::{CredentialStore, RecordKind};
use serde_json::Value;
use url::Url;

use crate::store_contract::key;
use crate::support::fakes::clock::START;
use crate::support::fakes::user::{Act, User};
use crate::support::oauth_server::OAuthServer;
use crate::support::{Harness, Outcome};

/// The server name every test uses.
pub(crate) const NAME: &str = "demo";

/// A harness with server `demo` on `server`'s MCP URL; `extra` follows
/// the URL line, so it may add server keys and then other tables.
pub(crate) fn harness(server: &OAuthServer, extra: &str) -> Harness {
    let h = Harness::new();
    h.write_config(&format!(
        "[servers.demo]\nurl = \"{}\"\n{extra}",
        server.mcp_url()
    ));
    h
}

/// An `auth_required` error carrying a challenge.
pub(crate) fn refusal(
    status: u16,
    error: Option<&str>,
    scope: Option<&str>,
    metadata: Option<Url>,
) -> Error {
    Error::new(ErrorKind::AuthRequired, "the server requires authorization").with_challenge(
        Challenge {
            status,
            resource_metadata: metadata,
            scope: scope.map(str::to_owned),
            error: error.map(str::to_owned),
        },
    )
}

/// A 401 naming `server`'s resource metadata.
pub(crate) fn unauthorized(server: &OAuthServer) -> Error {
    refusal(401, None, None, Some(server.resource_metadata()))
}

/// A 403 asking for `scope`.
pub(crate) fn needs_scope(scope: Option<&str>) -> Error {
    refusal(403, Some("insufficient_scope"), scope, None)
}

/// Runs `args` while a user watches stderr and does `act`.
pub(crate) fn run_watched(h: &Harness, args: &[&str], act: Act) -> Outcome {
    let mut out = Vec::new();
    let mut user = User::new(act);
    let code = h.run_with(args, &mut out, &mut user);
    Outcome {
        code,
        out: String::from_utf8(out).unwrap(),
        err: user.text(),
    }
}

/// Stdout as JSON, after checking the run succeeded.
pub(crate) fn reply(outcome: &Outcome) -> Value {
    assert_eq!(outcome.code, 0, "stderr: {}", outcome.err);
    serde_json::from_str(&outcome.out).unwrap()
}

/// The error from stderr's last line, after checking the run failed.
pub(crate) fn failure(outcome: &Outcome) -> (String, String) {
    assert_ne!(outcome.code, 0, "stdout: {}", outcome.out);
    let last = outcome.err.lines().last().unwrap();
    let error: Value = serde_json::from_str(last).unwrap();
    (
        error["error"]["kind"].as_str().unwrap().to_owned(),
        error["error"]["message"].as_str().unwrap().to_owned(),
    )
}

/// The `kind` record of `demo` in `store`.
pub(crate) fn stored<R: Record>(store: &dyn CredentialStore, kind: RecordKind) -> Option<R> {
    let key = key(NAME, kind);
    store
        .get(&key)
        .unwrap()
        .map(|bytes| record::decode(&key, &bytes).unwrap())
}

/// Stores `record` as `demo`'s `kind`.
pub(crate) fn seed<R: Record>(store: &dyn CredentialStore, kind: RecordKind, record: &R) {
    store
        .set(&key(NAME, kind), &record::encode(record))
        .unwrap();
}

/// Tokens `server` issued to `public-client`, valid for an hour, with
/// refresh token `rt-0`.
pub(crate) fn tokens(server: &OAuthServer) -> TokenRecord {
    TokenRecord {
        access_token: "at-0".to_owned(),
        refresh_token: Some("rt-0".to_owned()),
        expires_at: Some(START + 3600),
        token_type: "Bearer".to_owned(),
        scopes: vec!["read".to_owned()],
        issuer: server.base.clone(),
        resource: server.mcp_url(),
        client_id: "public-client".to_owned(),
        token_endpoint: server.base.join("token").unwrap(),
        pending_scopes: Vec::new(),
    }
}

/// `public-client`, dynamically registered with `server`.
pub(crate) fn client(server: &OAuthServer) -> RegistrationRecord {
    RegistrationRecord {
        issuer: server.base.clone(),
        client_id: "public-client".to_owned(),
        client_secret: None,
        token_endpoint_auth_method: TokenEndpointAuth::None,
        redirect_uri: Url::parse("http://127.0.0.1:1/callback").unwrap(),
        method: RegistrationMethod::Dynamic,
    }
}
