//! Command-line definitions. Parsing only; no behavior lives here.

use clap::{Args, Parser, Subcommand};

use crate::config::model::{OutputFormat, Transport};

/// The params argument that reads params from stdin.
pub(crate) const STDIN_PARAMS: &str = "-";

/// Call tools on remote HTTP MCP servers.
#[derive(Debug, Parser)]
#[command(name = "mcpjump", version, about, arg_required_else_help = true)]
pub(crate) struct Cli {
    /// Output format [default: from config, else json]
    #[arg(short = 'o', long = "output", global = true, value_enum)]
    pub(crate) output: Option<OutputFormat>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Add a remote server
    Add(AddArgs),
    /// Add a server from a Claude Code JSON definition
    AddJson(AddJsonArgs),
    /// List configured servers
    List,
    /// Show one server, with header values redacted
    Get(NameArg),
    /// Remove a server
    Remove(NameArg),
    /// List a server's tools, or show one tool's definition
    Tools(ToolsArgs),
    /// Call a tool
    Run(RunArgs),
    /// Log in to a server with OAuth in the browser
    Login(LoginArgs),
    /// Delete a server's tokens, keeping its client registration
    Logout(NameArg),
}

#[derive(Debug, Args)]
pub(crate) struct AddArgs {
    /// Transport: http detects the protocol generation; sse forces HTTP+SSE
    #[arg(short = 't', long = "transport", value_enum, default_value_t = Transport::Http)]
    pub(crate) transport: Transport,
    /// Static header "Name: value"; the value may use ${VAR} or ${VAR:-default}
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    pub(crate) headers: Vec<String>,
    /// Pre-registered OAuth client ID
    #[arg(long, value_name = "ID")]
    pub(crate) client_id: Option<String>,
    /// Fixed port for the OAuth callback; 0 picks a free port
    #[arg(long, value_name = "PORT", default_value_t = 0)]
    pub(crate) callback_port: u16,
    /// Config scope; only "user" exists, accepted for Claude Code compatibility
    #[arg(short = 's', long = "scope", value_name = "SCOPE", default_value = "user", value_parser = ["user"])]
    _scope: String,
    /// Server name: letters, digits, '_' or '-'
    pub(crate) name: String,
    /// Server URL (https, or http for localhost)
    pub(crate) url: String,
}

#[derive(Debug, Args)]
pub(crate) struct AddJsonArgs {
    /// Server name: letters, digits, '_' or '-'
    pub(crate) name: String,
    /// Claude Code server definition, e.g. '{"type":"http","url":"https://…"}'
    pub(crate) json: String,
}

#[derive(Debug, Args)]
pub(crate) struct ToolsArgs {
    /// Server name
    pub(crate) name: String,
    /// Show only this tool's full definition
    pub(crate) tool: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    /// Server name
    pub(crate) name: String,
    /// Tool name
    pub(crate) tool: String,
    /// Params as a JSON object, or - to read them from stdin [default: {}]
    pub(crate) params: Option<String>,
    /// Seconds the whole command may take [default: `limits.tool_timeout_secs`]
    #[arg(long, value_name = "SECS", value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub(crate) timeout: Option<u64>,
}

#[derive(Debug, Args)]
pub(crate) struct NameArg {
    /// Server name
    pub(crate) name: String,
}

#[derive(Debug, Args)]
pub(crate) struct LoginArgs {
    /// Server name
    pub(crate) name: String,
    /// Print the authorization URL without opening a browser
    #[arg(long)]
    pub(crate) no_browser: bool,
}
