//! mcpjump: call tools on remote HTTP MCP servers from the command line.
//!
//! This library exists for the `mcpjump` binary and its tests. Its API carries
//! no semver guarantee.

mod app;
pub mod auth;
mod cli;
mod commands;
pub mod config;
pub mod error;
pub mod files;
pub mod http;
pub mod mcp;
mod output;
pub mod store;
pub mod sys;

pub use app::{Deps, run};
