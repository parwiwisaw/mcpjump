# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - Unreleased

### Added

- Remote server configuration with `add`, `add-json`, `list`, `get`, and `remove`.
- `tools` for fresh tool discovery and schemas; `run` for inline JSON or stdin
  params with schema validation and raw MCP result output.
- An in-house MCP client for Modern MCP (2026-07-28), Legacy Streamable HTTP,
  and HTTP+SSE (2024-11-05), with saved protocol detection. `rmcp` is used only
  for message types.
- OAuth login with PKCE S256, browser or pasted redirect, pre-registered clients,
  Client ID Metadata Documents, and dynamic client registration.
- Automatic token refresh with per-server locking, resource and client binding,
  and local logout that retains registration.
- OS keyring storage and explicit or unavailable-keyring file fallback.
- JSON and escaped text output, documented exit codes, bounded HTTP and SSE,
  pagination and schema limits, and ambiguous-delivery errors without retries.
- Local Rust quality gates and CI configuration with 100% line, function,
  region, and branch coverage requirements.
- Release configuration for five native platforms, shell and PowerShell
  installers, Homebrew, and npm packages that work with install scripts disabled.
- Static Linux musl builds with the mimalloc allocator.

Release channels are being prepared; this entry does not mark a published release.
