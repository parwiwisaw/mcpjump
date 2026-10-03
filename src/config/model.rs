//! The typed configuration and its conversion from the raw TOML shape.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::limits::Limits;
use crate::config::validate::{self, HeaderTemplate, ServerName};
use crate::error::{Error, ErrorKind};

/// Most servers in one config file.
pub const MAX_SERVERS: usize = 256;

/// Where credentials are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStoreKind {
    /// The OS keyring, falling back to a file only when no keyring exists.
    #[default]
    Auto,
    /// The OS keyring only.
    Keyring,
    /// A permission-restricted file only.
    File,
}

/// Output format for results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    /// JSON on stdout.
    #[default]
    Json,
    /// Human-readable text on stdout.
    Text,
}

/// Transport requested for a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Streamable HTTP; the protocol generation is detected.
    #[default]
    Http,
    /// Legacy HTTP+SSE only.
    Sse,
}

impl Transport {
    /// The config and output spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Sse => "sse",
        }
    }
}

/// Protocol generation detected for a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Generation {
    /// MCP 2026-07-28, stateless.
    Modern,
    /// Streamable HTTP with `initialize` and sessions (2025-03-26 to 2025-11-25).
    LegacyStreamable,
    /// HTTP+SSE (2024-11-05).
    Sse,
}

impl Generation {
    /// The config file spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Modern => "modern",
            Self::LegacyStreamable => "legacy_streamable",
            Self::Sse => "sse",
        }
    }
}

/// Credential backend used at the last login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    /// The OS keyring.
    Keyring,
    /// The fallback file.
    File,
}

impl Backend {
    /// How `list` and `get` show the backend.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Keyring => "keyring",
            Self::File => "file (unencrypted)",
        }
    }
}

/// `[settings]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Settings {
    /// Credential backend policy.
    pub credential_store: CredentialStoreKind,
    /// Default output format.
    pub output: OutputFormat,
    /// Client ID Metadata Document URL; `None` disables CIMD.
    pub client_metadata_url: Option<Url>,
}

/// A server as the user defines it with `add` or `add-json`, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSpec {
    url: Url,
    transport: Transport,
    headers: Vec<HeaderTemplate>,
    client_id: Option<String>,
    callback_port: u16,
}

impl ServerSpec {
    /// Validates the URL, the header set and the client ID.
    ///
    /// # Errors
    /// `invalid_url`, `invalid_header` or `usage` naming the broken rule.
    pub fn new(
        url: &str,
        transport: Transport,
        headers: Vec<HeaderTemplate>,
        client_id: Option<String>,
        callback_port: u16,
    ) -> Result<Self, Error> {
        let url = validate::parse_server_url(url)?;
        validate::check_header_set(&headers)?;
        client_id.as_deref().map_or(Ok(()), check_client_id)?;
        Ok(Self {
            url,
            transport,
            headers,
            client_id,
            callback_port,
        })
    }

    /// Server URL.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Requested transport.
    #[must_use]
    pub const fn transport(&self) -> Transport {
        self.transport
    }

    /// Static headers.
    #[must_use]
    pub fn headers(&self) -> &[HeaderTemplate] {
        &self.headers
    }

    /// Pre-registered OAuth client ID.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    /// Fixed OAuth callback port; 0 picks a free port.
    #[must_use]
    pub const fn callback_port(&self) -> u16 {
        self.callback_port
    }
}

/// One `[servers.<name>]` entry: the user's definition plus what mcpjump
/// recorded about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEntry {
    /// The user's definition.
    pub spec: ServerSpec,
    /// Detected protocol generation, if probed.
    pub generation: Option<Generation>,
    /// Credential backend used at the last login.
    pub credentials: Option<Backend>,
}

/// The whole configuration, validated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    /// `[settings]`.
    pub settings: Settings,
    /// `[limits]`.
    pub limits: Limits,
    /// `[servers.*]`, by name.
    pub servers: BTreeMap<ServerName, ServerEntry>,
}

impl Config {
    /// Looks up a server by name.
    ///
    /// # Errors
    /// `unknown_server` if it is not configured.
    pub fn server(&self, name: &ServerName) -> Result<&ServerEntry, Error> {
        self.servers.get(name).ok_or_else(|| unknown_server(name))
    }
}

/// The error for a server name that is not configured.
#[must_use]
pub fn unknown_server(name: &ServerName) -> Error {
    Error::new(
        ErrorKind::UnknownServer,
        format!("no server named {:?}; see `mcpjump list`", name.as_str()),
    )
}

/// Validates a pre-registered OAuth client ID: 1 to 512 printable ASCII characters.
///
/// # Errors
/// `usage` if the ID is empty, too long, or has other characters.
pub fn check_client_id(client_id: &str) -> Result<(), Error> {
    let printable = client_id.bytes().all(|b| (0x20..=0x7e).contains(&b));
    if client_id.is_empty() || client_id.len() > 512 || !printable {
        return Err(Error::new(
            ErrorKind::Usage,
            "invalid client ID: use 1 to 512 printable ASCII characters",
        ));
    }
    Ok(())
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RawConfig {
    settings: RawSettings,
    limits: Limits,
    servers: BTreeMap<String, RawServer>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawSettings {
    credential_store: CredentialStoreKind,
    output: OutputFormat,
    client_metadata_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    url: String,
    #[serde(default)]
    transport: Transport,
    generation: Option<Generation>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    callback_port: u16,
    credentials: Option<Backend>,
}

impl RawConfig {
    /// Validates every value and builds the typed config.
    pub(crate) fn validate(self) -> Result<Config, Error> {
        if self.servers.len() > MAX_SERVERS {
            return Err(too_many_servers());
        }
        check_server_name_uniqueness(self.servers.keys().map(String::as_str))?;
        self.limits.validate()?;
        let settings = self.settings.validate()?;
        let mut servers = BTreeMap::new();
        for (name, raw) in self.servers {
            let key = format!("servers.{name}");
            let name = ServerName::parse(&name).map_err(|error| error.in_config_key(&key))?;
            let entry = raw.validate().map_err(|error| error.in_config_key(&key))?;
            servers.insert(name, entry);
        }
        Ok(Config {
            settings,
            limits: self.limits,
            servers,
        })
    }
}

/// Checks only bounded name uniqueness, so an update can still repair
/// unrelated invalid fields. Oversized names are rejected by normal validation.
pub(crate) fn check_server_name_uniqueness<'a>(
    names: impl Iterator<Item = &'a str>,
) -> Result<(), Error> {
    let mut folded = BTreeMap::new();
    for (index, name) in names.enumerate() {
        if index >= MAX_SERVERS {
            return Err(too_many_servers());
        }
        if name.len() > validate::MAX_NAME_LEN {
            continue;
        }
        if let Some(previous) = folded.insert(name.to_ascii_lowercase(), name) {
            return Err(Error::new(
                ErrorKind::ConfigInvalid,
                format!(
                    "server names {previous:?} and {name:?} differ only in ASCII case; \
                     choose distinct names in config.toml before using their credentials"
                ),
            ));
        }
    }
    Ok(())
}

/// The error for a config that would hold more than [`MAX_SERVERS`] servers.
#[must_use]
pub fn too_many_servers() -> Error {
    Error::new(
        ErrorKind::ConfigTooLarge,
        format!("too many servers: at most {MAX_SERVERS}"),
    )
}

impl RawSettings {
    fn validate(self) -> Result<Settings, Error> {
        let client_metadata_url = match self.client_metadata_url.as_str() {
            "" => None,
            raw => Some(
                validate::parse_server_url(raw)
                    .map_err(|error| error.in_config_key("settings.client_metadata_url"))?,
            ),
        };
        Ok(Settings {
            credential_store: self.credential_store,
            output: self.output,
            client_metadata_url,
        })
    }
}

impl RawServer {
    fn validate(self) -> Result<ServerEntry, Error> {
        let headers = self
            .headers
            .iter()
            .map(|(name, value)| HeaderTemplate::parse(name, value))
            .collect::<Result<Vec<_>, _>>()?;
        let client_id = Some(self.client_id).filter(|id| !id.is_empty());
        let spec = ServerSpec::new(
            &self.url,
            self.transport,
            headers,
            client_id,
            self.callback_port,
        )?;
        Ok(ServerEntry {
            spec,
            generation: self.generation,
            credentials: self.credentials,
        })
    }
}
