# mcpjump

Call tools on remote HTTP MCP servers from the command line. Add a server, log in
if it needs OAuth, inspect its tools, and call them with JSON arguments.

Results are JSON by default, so agents and shell scripts can use the same commands
as people. mcpjump supports Modern MCP, Legacy Streamable HTTP, and HTTP+SSE through
its own bounded HTTP client. `rmcp` supplies message types only.

> **Release status:** 0.1.0 is prepared locally and has not been published. Build
> from this checkout today; the other installation channels below describe the
> planned release.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Agent and script usage](#agent-and-script-usage)
- [Configuration](#configuration)
- [Authentication and credential storage](#authentication-and-credential-storage)
- [Protocol support](#protocol-support)
- [Development](#development)
- [License](#license)

## Installation

### Build and install from source

Requires Git, Rust 1.89 or newer, and the platform's native build tools. Follow
[the Rust installation guide](https://rust-lang.org/tools/install/) to install
Rust and Cargo. macOS needs the Xcode Command Line Tools; Linux needs a C compiler
and linker; Windows needs the MSVC C++ build tools described in the Rust guide.
Open a new terminal after installing Rust, then check:

```sh
rustc --version
cargo --version
```

The following commands use a POSIX shell on macOS or Linux. Once the public
GitHub repository exists, clone it to your machine:

```sh
mkdir -p ~/code/personal-public
git clone https://github.com/parwiwisaw/mcpjump.git ~/code/personal-public/mcpjump
```

If you already have this checkout, skip the clone. Build and run the local binary:

```sh
cargo build --locked --release --manifest-path ~/code/personal-public/mcpjump/Cargo.toml
~/code/personal-public/mcpjump/target/release/mcpjump --version
```

To install the command for use from any directory:

```sh
cargo install --locked --path ~/code/personal-public/mcpjump
mcpjump --version
```

`cargo install` builds the release binary and installs it into `~/.cargo/bin` by
[default](https://doc.rust-lang.org/cargo/commands/cargo-install.html). If the
installed command is not found, add that directory to your shell's PATH. For the
current terminal:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
mcpjump --version
```

To update an existing checkout and reinstall:

```sh
git -C ~/code/personal-public/mcpjump pull --ff-only
cargo install --locked --path ~/code/personal-public/mcpjump
mcpjump --version
```

### Planned release channels

These commands become available after the repository and package names are
registered and the first release is published.

| Channel | Install command |
| --- | --- |
| npm (Node.js 22 or newer) | `npm install -g mcpjump --ignore-scripts` |
| crates.io | `cargo install mcpjump --locked` |
| cargo-binstall | `cargo binstall mcpjump` |
| Homebrew | `brew install parwiwisaw/tap/mcpjump` |

The npm package selects a native binary through an exact-version optional
dependency. Neither the wrapper nor the platform packages need install scripts.

Release archives, SHA-256 checksums, and shell and PowerShell installers will be
available on [GitHub Releases](https://github.com/parwiwisaw/mcpjump/releases).
Planned platforms are Apple Silicon and Intel macOS, Linux arm64 and x64 (static
musl binaries for glibc and musl systems), and Windows x64. Windows arm64 is outside
the MVP.

Once released, the shell installer can be downloaded and inspected before use:

```sh
curl --proto '=https' --tlsv1.2 -fL --max-time 60 \
  https://github.com/parwiwisaw/mcpjump/releases/latest/download/mcpjump-installer.sh \
  -o ~/Downloads/mcpjump-installer.sh
sh ~/Downloads/mcpjump-installer.sh
```

On Windows, download and inspect the PowerShell installer before running it:

```powershell
Invoke-WebRequest -TimeoutSec 60 -Uri https://github.com/parwiwisaw/mcpjump/releases/latest/download/mcpjump-installer.ps1 -OutFile ~/Downloads/mcpjump-installer.ps1
& ~/Downloads/mcpjump-installer.ps1
```

Release macOS binaries are unsigned; see the Keychain note below.

## Quick start

```sh
mcpjump add docs https://docs.mcp.cloudflare.com/mcp
mcpjump tools docs
```

For a server that needs OAuth:

```sh
mcpjump add work https://example.com/mcp
mcpjump login work
mcpjump tools work
```

Replace `example.com` with your server. Choose a tool from the returned list,
inspect its schema, then send the JSON object that schema expects:

```sh
mcpjump tools work search
mcpjump run work search '{"query":"release notes"}'
```

`search` and its arguments are illustrative: tool names and schemas come from
each server. Adding a server changes local configuration; it does not contact the
server or log in.

## Commands

```text
mcpjump add [-t http|sse] [-H "Name: value"]... [--client-id ID]
            [--callback-port PORT] [-s user] NAME URL
mcpjump add-json NAME JSON
mcpjump list
mcpjump get NAME
mcpjump remove NAME
mcpjump login NAME [--no-browser]
mcpjump logout NAME
mcpjump tools NAME [TOOL]
mcpjump run NAME TOOL [PARAMS_JSON | -] [--timeout SECS]
```

Use `-o json` or `-o text` before or after a command to choose output format.
`--help` on a command gives its full argument reference.

- `add` accepts HTTPS, or HTTP on loopback. Names use 1–64 ASCII letters,
  digits, underscores, or hyphens, starting with a letter or digit. `-t http`
  detects the generation; `-t sse` forces HTTP+SSE. Only `-s user` exists.
- `add-json` accepts a Claude Code HTTP or SSE server definition. stdio servers
  and project or local scopes are unsupported.
- `get` shows configuration with every header value redacted. `remove` also
  deletes stored tokens and client registration.
- `tools NAME` lists tools with their input schemas. `tools NAME TOOL` returns
  one tool's full definition. Lists are fetched fresh on each command.
- `run` defaults to `{}` when arguments are omitted. `--timeout` accepts 1–3600
  seconds and overrides the configured tool deadline.
- `logout` deletes local tokens and retains OAuth client registration. It does
  not revoke tokens on the server.

For a static header, prefer an environment reference so the secret is not written
into config or shell history:

```sh
mcpjump add api https://example.com/mcp -H 'Authorization: Bearer ${API_TOKEN}'
mcpjump add-json api2 '{"type":"http","url":"https://example.com/mcp","headers":{"X-Api-Key":"${API_KEY}"}}'
```

Export the referenced variable in the calling process. `${VAR:-default}` is also
supported. Literal header values are stored in the TOML config; `get` redaction
does not encrypt them.

## Agent and script usage

Keep JSON output enabled. Successful commands write their result to stdout;
errors, warnings, and login notices go to stderr. `run` returns the server's raw
MCP result, including fields mcpjump does not recognize. An MCP result with
`isError: true` stays on stdout and exits 1.

Use `tools` before constructing arguments. Params must be one JSON object and
must pass the tool's input schema. Use a quoted heredoc for values that are awkward
to quote on the command line:

```sh
mcpjump run work search - <<'JSON'
{"query":"What's changed?","limit":5}
JSON
```

Quoted heredocs prevent the shell from expanding variables or executing text in
the arguments. The tool and fields above remain illustrative.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | The tool returned `isError: true` |
| 2 | Bad command arguments, unknown server or tool, or invalid params |
| 3 | Login required, invalid credential binding, or login timeout |
| 4 | Network, server, protocol, resource-limit, or delivery failure |
| 5 | Local config, credential-store, locking, or output failure |

An error is one JSON line on stderr:

```json
{"error":{"kind":"invalid_params","message":"params are not valid JSON"}}
```

Schema errors may include a JSON pointer in `error.path`. After an ambiguous tool
delivery, the error also includes `execution`:

```json
{"error":{"kind":"delivery_unknown","message":"tool delivery could not be confirmed","execution":"unknown"}}
```

The message above illustrates the format. **Do not automatically retry a
`delivery_unknown` call:** the tool may already have run. mcpjump does not retry
an ambiguous call. A 401 can trigger one token refresh and one retry after an
explicit authentication rejection. `tools` and `run` never launch a browser;
handle exit 3 by asking a person to run `mcpjump login NAME`.

Text mode escapes terminal control characters in server-supplied data. Tool
results may contain sensitive or untrusted content; choose what to log or pass to
an agent accordingly.

## Configuration

The config is `config.toml` under:

| Platform | Default directory |
| --- | --- |
| macOS and other Unix systems | `$XDG_CONFIG_HOME/mcpjump`, else `~/.config/mcpjump` |
| Windows | `%APPDATA%\mcpjump` |
| Any platform with `MCPJUMP_HOME` set | The absolute directory in `MCPJUMP_HOME` |

`MCPJUMP_HOME` replaces the directory, not the filename. Set it to an absolute
path to isolate a test installation. The first config write includes every
default with comments; later changes preserve comments and formatting.

```toml
[settings]
credential_store = "auto"  # auto | keyring | file
output = "json"            # json | text
client_metadata_url = ""   # empty disables Client ID Metadata Documents

[limits]
connect_timeout_secs = 5
request_timeout_secs = 15
tool_timeout_secs = 120
login_timeout_secs = 300
keyring_timeout_secs = 3
lock_wait_secs = 20
max_response_bytes = 16777216
max_params_bytes = 1048576
max_tools = 1000
```

This is an excerpt; the generated config documents all limits and their allowed
ranges. `lock_wait_secs` must exceed `request_timeout_secs`. HTTP responses, SSE
events, tool-list pages and bytes, schema work, stdin, OAuth calls, and credential
operations have finite limits. Schema validation has its own deadline and may
add up to `validation_timeout_secs` beyond a tool deadline.

The saved `generation` and `credentials` fields under `[servers.NAME]` are
maintained by mcpjump. A saved credential backend takes precedence over the
global policy, so changing `settings.credential_store` alone does not migrate
existing credentials.

## Authentication and credential storage

`login` uses OAuth with PKCE S256, a loopback callback on `127.0.0.1`, and state
validation. It tries a pre-registered client ID, an enabled Client ID Metadata
Document, then dynamic registration when the server supports it. Public hosting
for a default metadata document has not been configured.

`tools` and `run` refresh expiring tokens and save rotated refresh tokens under a
per-server lock. Tokens are bound to the resource and OAuth client; a mismatched
registration or token requires login again.

### Storage policy

- `auto` uses macOS Keychain, Windows Credential Manager, or Linux Secret Service.
  It falls back to a file only when the keyring cannot start, with a warning.
- `keyring` requires the OS keyring.
- `file` explicitly stores credentials unencrypted under the config directory's
  `credentials` subdirectory. On Unix the directory is `0700` and files are
  `0600`. On Windows the store relies on inherited per-user ACLs.

A keyring that starts but is locked, denies access, or times out produces exit 5;
`auto` does not switch to file storage in these cases. The default keyring timeout
is 3 seconds. If a local permission dialog needs more time, set
`limits.keyring_timeout_secs` to a value up to 60 before retrying.

File storage protects against other Unix users through permissions, but is not
encrypted at rest. Keep the directory out of shared locations, backups you do not
control, and version control. On Windows, a custom `MCPJUMP_HOME` must have a
private ACL; mcpjump does not tighten or validate Windows ACLs.

To move an existing server to file storage, change its recorded
`credentials = "keyring"` to `credentials = "file"` under `[servers.NAME]`, set
`settings.credential_store = "file"` if desired, and run `login NAME` again.
This creates a fresh file login; it does not copy or delete the old keyring
record. Do not extract tokens from the keyring manually.

### macOS Keychain and unsigned builds

Unsigned binaries can cause a new Keychain permission prompt after each rebuild
or upgrade. Run a credential-using command at the Mac's screen and choose
**Always Allow** if you trust the binary. An SSH-only session may instead fail
with `credential_store: User interaction is not allowed` or `keyring_timeout`;
the permission dialog needs the local graphical session. File storage is an
explicit alternative for headless use. Signing and notarization are deferred.

### Login over SSH

```sh
mcpjump login work --no-browser
```

Open the printed authorization URL in a browser on your own computer. After
authorization, copy the complete redirect URL from the address bar, even if the
browser cannot connect to `127.0.0.1`, and paste it into the waiting SSH terminal.
The redirect carries a short-lived authorization code; do not share it or put it
in logs. Pasting is available when stdin is an interactive terminal.

Alternatively choose a fixed callback port and forward it from your computer:

```sh
mcpjump add work https://example.com/mcp --callback-port 8765
```

On your computer, connect to the SSH host with:

```sh
ssh -L 8765:127.0.0.1:8765 user@host
```

Then run `mcpjump login work --no-browser` in that session and open the printed
URL locally. Both ports must be free. Browser callback forwarding and Keychain
access are separate requirements.

## Protocol support

With `-t http`, mcpjump tries the saved generation first, then Modern
(`server/discover`, 2026-07-28), Legacy Streamable HTTP (`initialize`), and
HTTP+SSE (2024-11-05). A successful generation is saved for the next command.
Fallback needs an explicit unsupported-generation signal; authentication,
timeouts, TLS errors, and tool-call failures do not trigger a downgrade.

mcpjump advertises no client capabilities. Sampling, elicitation, roots,
subscriptions, resources and prompts commands, stdio transport, shell
completions, and persistent tool caches are outside this release.

## Development

Use a separate absolute `MCPJUMP_HOME` for manual experiments. Automated tests use
loopback fixtures and do not register clients with third-party OAuth servers.

```sh
cargo fmt --manifest-path ~/code/personal-public/mcpjump/Cargo.toml --check
cargo clippy --manifest-path ~/code/personal-public/mcpjump/Cargo.toml \
  --locked --all-targets -- -D warnings
cargo test --manifest-path ~/code/personal-public/mcpjump/Cargo.toml --locked
```

The project also requires rustdoc, MSRV 1.89, dependency and composition checks,
and 100% line, function, region, and branch coverage. The OS keyring contract
needs an unlocked native keyring. Full gate commands are recorded in the handoff;
cross-platform verification runs in CI after an approved push.

Release workflows use cargo-dist 0.33.0. After changing its configuration, run
`python3 ~/code/personal-public/mcpjump/ci/normalize_dist_workflow.py` with `dist`
installed. The command regenerates the workflow and applies checked quoting and
redirection fixes to the pinned template. CI checks the result against the committed
workflow, and runs actionlint with ShellCheck.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](https://github.com/parwiwisaw/mcpjump/blob/main/LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](https://github.com/parwiwisaw/mcpjump/blob/main/LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
