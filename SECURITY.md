# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/parwiwisaw/mcpjump/security/advisories/new).
Do not open a public issue.

The public repository and reporting channel are pending registration. Until that
channel exists, report privately to the repository owner through an existing
private contact rather than posting credential material publicly.

Include the mcpjump version, your operating system, and the steps to reproduce.
Never include real access tokens, refresh tokens, or client secrets in a report.

## Supported versions

Only the latest release receives security fixes. No version has been released yet.

## Credential storage

OAuth access tokens, refresh tokens, and dynamic-registration client secrets are
stored in macOS Keychain, Windows Credential Manager, or Linux Secret Service by
default. Records are validated when read and bound to their resource, issuer,
and OAuth client. Per-server locks protect rotating tokens across CLI processes.
Large keyring records are stored in bounded chunks with a checksum and a commit
manifest, so an interrupted update preserves the last committed record.

With `credential_store = "auto"`, file fallback happens only if the keyring
cannot start. A locked keyring, denied access, or a timeout is an error rather
than an automatic migration. The chosen backend is recorded per server and takes
precedence over later global policy changes.

File credentials live unencrypted in the config directory's `credentials`
subdirectory. Unix directories use mode `0700` and files use `0600`; unsafe modes,
symlinks, and non-regular credential files are refused. Anyone with access to the
account, its backups, or the filesystem as an administrator can still read them.
Choose file storage deliberately, keep that directory private, and exclude it
from source control and shared or untrusted backups.

On Windows, the file store relies on the inherited per-user `%APPDATA%` ACL. It
does not apply or validate ACLs. A custom `MCPJUMP_HOME`, especially on a shared
drive or directory, must have an ACL limited to the intended user and trusted
administrators. This limitation applies to both explicit file storage and
automatic fallback.

Static header values are stored in config, outside the credential store. Prefer
`${VARIABLE}` references over literal secrets. `get` redacts all header values,
but redaction does not encrypt config or protect shell history.

`logout` deletes local tokens and retains client registration; it does not revoke
tokens with the authorization server. `remove` deletes the local registration
as well. Changing a server's recorded backend does not erase records in its old
backend.

## OAuth and headless access

Login uses PKCE S256, a state value, and an exact loopback redirect on
`127.0.0.1`. Callback requests and pasted redirect URLs are checked against the
same flow. Authorization-server issuer checks follow the selected discovery
profile. Network calls, browser launch, callback waiting, and keyring operations
have finite deadlines.

The authorization URL is intentionally shown during login. A redirected URL
contains a short-lived authorization code; do not share it in reports, logs, or
chat. `tools` and `run` never open a browser. They can refresh a stored token and
otherwise require an explicit login.

macOS release builds are currently unsigned. Rebuilds and upgrades may need a
new **Always Allow** approval at the Mac's screen. SSH sessions cannot answer
that dialog and may return a keyring error or timeout. Code signing and
notarization are deferred.

## URL and HTTP policy

Configured server URLs require HTTPS, except HTTP on loopback-class hosts.
User information in URLs and fragments are rejected. Advertised metadata and
OAuth URLs require HTTPS, except loopback HTTP for a server already configured
on loopback HTTP. Loopback includes `localhost`, `*.localhost`, loopback IPs,
and unspecified addresses.

Advertised literal private, link-local, or loopback addresses are rejected when
the configured server is not in the same address class. Public hostnames are
not checked against their DNS-resolved addresses. DNS rebinding and a hostname
resolving to a private address remain outside the MVP's protections; do not use
an untrusted server as a general network-isolation boundary.

Configured headers and bearer tokens are sent only to the configured server's
origin. Legacy SSE message endpoints must share that origin. Allowed HTTP
redirects stay on the same origin and have a hop cap; credential-bearing OAuth
POSTs do not follow redirects. Responses, metadata, SSE lines and events, tool
lists, params, and schema work have byte, count, depth, or time bounds.

## Output and tool execution

Error messages omit tokens, authorization codes, header values, params, and full
request URLs. Text results escape terminal control characters. Successful
results are server-controlled data and may themselves contain sensitive content
or instructions; treat them as untrusted and decide what to log.

An interrupted tool call can have an unknown execution outcome. mcpjump reports
`delivery_unknown` with `execution = "unknown"` and does not automatically retry
it. Check the server's state before deciding whether to call a tool again.
