//! The top-level error type and the closed set of error kinds with their exit codes.

use std::fmt;

use crate::auth::challenge::Challenge;

/// Every error the CLI reports. `as_str` is the public `kind` string and
/// `exit_code` the documented exit code; both are part of the CLI contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Bad command-line usage.
    Usage,
    /// The named server is not configured.
    UnknownServer,
    /// A server with that name already exists.
    ServerExists,
    /// A server name breaks the naming rule.
    InvalidName,
    /// A server URL breaks the URL rules.
    InvalidUrl,
    /// A header breaks the header rules.
    InvalidHeader,
    /// A JSON server definition is malformed or unsupported.
    InvalidDefinition,
    /// A `${VAR}` reference names an unset variable.
    MissingEnvVar,
    /// The config file is malformed or holds an out-of-range value.
    ConfigInvalid,
    /// The config file or server count exceeds its limit.
    ConfigTooLarge,
    /// The config file or directory cannot be read or written.
    ConfigIo,
    /// Another process held the config lock for too long.
    ConfigLockTimeout,
    /// Output could not be written.
    OutputIo,
    /// The credential store failed: a locked or denied keyring, or a
    /// credential file that is unsafe or unreadable.
    CredentialStore,
    /// A stored credential is corrupt or fails validation.
    CredentialInvalid,
    /// A credential record exceeds the size every backend can hold.
    CredentialTooLarge,
    /// Another process held a server's credential lock for too long.
    CredentialLockTimeout,
    /// The OS keyring did not answer within `keyring_timeout_secs`.
    KeyringTimeout,
    /// The server could not be reached: DNS, refused connection, TLS, or a
    /// connection that broke mid-response.
    Network,
    /// No connection was made within `connect_timeout_secs`.
    ConnectTimeout,
    /// A request did not finish before its deadline.
    RequestTimeout,
    /// A stream went idle for `stream_idle_secs` or outlived its deadline.
    StreamTimeout,
    /// A redirect left the origin, went past the hop limit, or was not allowed
    /// for the request.
    RedirectRejected,
    /// A response or SSE event exceeded `max_response_bytes`.
    ResponseTooLarge,
    /// A metadata document exceeded `max_metadata_bytes`.
    MetadataTooLarge,
    /// A URL the server advertised breaks the URL policy.
    UrlRejected,
    /// The server asked for authentication (401) or refused access (403),
    /// or the stored credentials cannot be used.
    AuthRequired,
    /// The authorization server's resource does not cover the server URL.
    ResourceMismatch,
    /// The browser login did not finish within `login_timeout_secs`.
    LoginTimeout,
    /// Authorization requests did not finish within
    /// `auth_network_budget_secs`.
    AuthTimeout,
    /// The server answered with an unexpected HTTP status.
    HttpStatus,
    /// Tool params are not a JSON object, exceed a limit, or fail the schema.
    InvalidParams,
    /// The server does not list the named tool.
    UnknownTool,
    /// Tool discovery passed a page, count or size limit, or repeated a cursor.
    ToolListLimit,
    /// No supported protocol generation answered.
    UnsupportedServer,
    /// A legacy session expired again after one re-initialization.
    SessionLost,
    /// A tool call failed after it may have reached the server; it may or may
    /// not have run.
    DeliveryUnknown,
    /// A tool's input schema is too large, too deep, or too slow to check.
    SchemaTooComplex,
    /// The server needs a feature mcpjump does not support.
    UnsupportedFeature,
    /// The server broke the MCP protocol.
    ProtocolError,
    /// The server answered a request with a JSON-RPC error.
    ServerError,
}

impl ErrorKind {
    /// Every kind, for contract tests.
    pub const ALL: [Self; 41] = [
        Self::Usage,
        Self::UnknownServer,
        Self::ServerExists,
        Self::InvalidName,
        Self::InvalidUrl,
        Self::InvalidHeader,
        Self::InvalidDefinition,
        Self::MissingEnvVar,
        Self::ConfigInvalid,
        Self::ConfigTooLarge,
        Self::ConfigIo,
        Self::ConfigLockTimeout,
        Self::OutputIo,
        Self::CredentialStore,
        Self::CredentialInvalid,
        Self::CredentialTooLarge,
        Self::CredentialLockTimeout,
        Self::KeyringTimeout,
        Self::Network,
        Self::ConnectTimeout,
        Self::RequestTimeout,
        Self::StreamTimeout,
        Self::RedirectRejected,
        Self::ResponseTooLarge,
        Self::MetadataTooLarge,
        Self::UrlRejected,
        Self::AuthRequired,
        Self::ResourceMismatch,
        Self::LoginTimeout,
        Self::AuthTimeout,
        Self::HttpStatus,
        Self::InvalidParams,
        Self::UnknownTool,
        Self::ToolListLimit,
        Self::UnsupportedServer,
        Self::SessionLost,
        Self::DeliveryUnknown,
        Self::SchemaTooComplex,
        Self::UnsupportedFeature,
        Self::ProtocolError,
        Self::ServerError,
    ];

    /// The public `snake_case` name of this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::UnknownServer => "unknown_server",
            Self::ServerExists => "server_exists",
            Self::InvalidName => "invalid_name",
            Self::InvalidUrl => "invalid_url",
            Self::InvalidHeader => "invalid_header",
            Self::InvalidDefinition => "invalid_definition",
            Self::MissingEnvVar => "missing_env_var",
            Self::ConfigInvalid => "config_invalid",
            Self::ConfigTooLarge => "config_too_large",
            Self::ConfigIo => "config_io",
            Self::ConfigLockTimeout => "config_lock_timeout",
            Self::OutputIo => "output_io",
            Self::CredentialStore => "credential_store",
            Self::CredentialInvalid => "credential_invalid",
            Self::CredentialTooLarge => "credential_too_large",
            Self::CredentialLockTimeout => "credential_lock_timeout",
            Self::KeyringTimeout => "keyring_timeout",
            Self::Network => "network",
            Self::ConnectTimeout => "connect_timeout",
            Self::RequestTimeout => "request_timeout",
            Self::StreamTimeout => "stream_timeout",
            Self::RedirectRejected => "redirect_rejected",
            Self::ResponseTooLarge => "response_too_large",
            Self::MetadataTooLarge => "metadata_too_large",
            Self::UrlRejected => "url_rejected",
            Self::AuthRequired => "auth_required",
            Self::ResourceMismatch => "resource_mismatch",
            Self::LoginTimeout => "login_timeout",
            Self::AuthTimeout => "auth_timeout",
            Self::HttpStatus => "http_status",
            Self::InvalidParams => "invalid_params",
            Self::UnknownTool => "unknown_tool",
            Self::ToolListLimit => "tool_list_limit",
            Self::UnsupportedServer => "unsupported_server",
            Self::SessionLost => "session_lost",
            Self::DeliveryUnknown => "delivery_unknown",
            Self::SchemaTooComplex => "schema_too_complex",
            Self::UnsupportedFeature => "unsupported_feature",
            Self::ProtocolError => "protocol_error",
            Self::ServerError => "server_error",
        }
    }

    /// The process exit code for this kind.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Usage
            | Self::UnknownServer
            | Self::ServerExists
            | Self::InvalidName
            | Self::InvalidUrl
            | Self::InvalidHeader
            | Self::InvalidDefinition
            | Self::MissingEnvVar
            | Self::InvalidParams
            | Self::UnknownTool => 2,
            Self::AuthRequired | Self::ResourceMismatch | Self::LoginTimeout => 3,
            Self::ConfigInvalid
            | Self::ConfigTooLarge
            | Self::ConfigIo
            | Self::ConfigLockTimeout
            | Self::OutputIo
            | Self::CredentialStore
            | Self::CredentialInvalid
            | Self::CredentialTooLarge
            | Self::CredentialLockTimeout
            | Self::KeyringTimeout => 5,
            Self::Network
            | Self::ConnectTimeout
            | Self::RequestTimeout
            | Self::StreamTimeout
            | Self::RedirectRejected
            | Self::ResponseTooLarge
            | Self::MetadataTooLarge
            | Self::UrlRejected
            | Self::HttpStatus
            | Self::AuthTimeout
            | Self::ToolListLimit
            | Self::UnsupportedServer
            | Self::SessionLost
            | Self::DeliveryUnknown
            | Self::SchemaTooComplex
            | Self::UnsupportedFeature
            | Self::ProtocolError
            | Self::ServerError => 4,
        }
    }
}

/// An error with its kind, a message safe to show, an optional JSON
/// pointer, and the server's challenge when it refused access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    path: Option<String>,
    challenge: Option<Box<Challenge>>,
}

impl Error {
    /// Creates an error. The message must never contain secrets.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            path: None,
            challenge: None,
        }
    }

    /// Attaches the `WWW-Authenticate` challenge of a 401 or 403.
    #[must_use]
    pub fn with_challenge(mut self, challenge: Challenge) -> Self {
        self.challenge = Some(Box::new(challenge));
        self
    }

    /// The challenge of a 401 or 403, if the server sent one.
    #[must_use]
    pub fn challenge(&self) -> Option<&Challenge> {
        self.challenge.as_deref()
    }

    /// Attaches a JSON pointer to the offending input.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Re-labels a validation error found while loading the config file,
    /// naming the config key that holds the bad value.
    #[must_use]
    pub fn in_config_key(self, key: &str) -> Self {
        Self::new(ErrorKind::ConfigInvalid, format!("{key}: {}", self.message))
    }

    /// The error kind.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The human-readable message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The JSON pointer to the offending input, if any.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}
