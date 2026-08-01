# Reference

## CLI Flags

### Basic Usage

```
mcp-stdio [OPTIONS] URL

Arguments:
  URL                    Remote MCP server URL
```

### Authentication

| Flag | Environment Variable | Description |
|------|----------------------|-------------|
| `--bearer-token TOKEN` | `MCP_BEARER_TOKEN` | Static bearer token for authentication |
| `--oauth` | — | Enable OAuth 2.1 authentication (browser flow) |
| `--oauth-device` | — | Enable OAuth 2.1 Device Authorization Grant (RFC 8628, headless) |
| `--client-id ID` | `MCP_OAUTH_CLIENT_ID` | Pre-registered OAuth client ID (skips Dynamic Client Registration) |
| `--client-metadata-url URL` | — | HTTPS URL of a Client ID Metadata Document to use as client_id instead of DCR |
| `--oauth-scope SCOPE` | — | OAuth scope(s) to request, space-separated in one value (e.g. `"openid offline_access"`). When the server grants a scope that differs from the one previously granted (e.g. a downgrade), mcp-stdio logs `authorization server granted scope: …` to stderr; unchanged refreshes stay quiet |
| `--oauth-use-id-token` | — | Present the OIDC id_token as the Bearer credential instead of access_token (AWS Bedrock / Cognito) |
| `--oauth-eager` | — | Cold-start: answer initialize locally and run interactive OAuth in the background, so a long login does not exceed the client's ~60 s timeout |
| `--oauth-refresh-leeway SECONDS` | `MCP_OAUTH_REFRESH_LEEWAY` | Proactively refresh tokens this many seconds before expiry (default: 60) |
| `--no-proactive-refresh` | — | Disable the background timer that refreshes the OAuth token before it expires |
| `--oauth-timeout SECONDS` | — | Seconds to wait for the interactive OAuth flow (browser callback / device-code confirmation) before giving up (default: 120) |
| `--no-resource-indicator` | — | Omit the RFC 8707 resource parameter from all OAuth requests. Required for some authorization servers that reject it (e.g. Microsoft Entra ID with api:// scopes) |
| `--oauth-resource URI` | — | Send this exact RFC 8707 resource value on every OAuth request instead of the server-URL-derived one. Required for AS that demand a specific resource identifier, e.g. Entra ID's App ID URI `api://<app-id>`. Persisted in the token store. Mutually exclusive with `--no-resource-indicator` |

### Transport

| Flag | Default | Description |
|------|---------|-------------|
| `--transport {streamable-http,sse}` | `streamable-http` | Transport type (Streamable HTTP is current MCP spec; SSE is legacy 2024-11-05) |
| `--timeout-connect SEC` | 10 | Connection timeout in seconds |
| `--timeout-read SEC` | 120 | Read timeout in seconds |
| `--sse-read-timeout SEC` | 300 | Idle read timeout on the SSE GET stream (SSE transport only; 0 disables) |
| `--no-tcp-keepalive` | — | Disable TCP keepalive on the HTTP socket |

<a id="modern-era-client"></a>

### Newer MCP servers (2026-07-28)

Only needed when the server you connect to was built for the newer MCP
spec. See [Working with MCP 2026-07-28 servers](modes.md#protocol-eras).

| Flag | Default | Description |
|------|---------|-------------|
| `--protocol-era {legacy,modern,auto}` | `legacy` | How to talk to the remote server. `legacy` behaves exactly as before; `auto` asks the server once at startup and picks for you; `modern` skips the question when you already know it is a newer server. Ignored (with a warning) on `--transport sse` |
| `--listen-read-timeout SEC` | `300` | How long to wait on a quiet notification connection before reconnecting. Only used against newer servers. Unlike `--sse-read-timeout`, `0` is not allowed — the connection always needs a timeout. Silently ignored on `--transport sse` |

!!! note "What `--check` does and does not cover"
    `--check` confirms the server is reachable either way — if the older
    handshake is refused it retries the way a newer server expects, so a
    newer-only server still reports ✓. It is a connectivity check, though:
    it does not exercise the rest of the newer behaviour, such as the
    long-lived notification connection.


### Headers & Proxies

| Flag | Description |
|------|-------------|
| `-H, --header 'Key: Value'` | Custom header (repeatable); headers are included on every request |
| — | Proxies are honored via standard `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` env vars |

### Behavior

| Flag | Description |
|------|-------------|
| `--no-cancel-filter` | Disable the cancel-aware response filter (drops late responses for ids cancelled via notifications/cancelled) |
| `--no-normalize-arguments` | Disable rewriting a tools/call request's arguments:null to {} before forwarding |

### Utilities

| Flag | Description |
|------|-------------|
| `--check` | Check connection and exit. Runs the whole path once: discovery, OAuth login (if applicable), token exchange, and an MCP initialize round-trip |
| `-V, --version` | Show version |
| `-h, --help` | Show help |

Run `mcp-stdio --help` for full per-flag detail including platform notes and issue references.

---

## Serve Mode

`mcp-stdio serve` exposes a local stdio MCP server as a Streamable HTTP endpoint. See [Publish your stdio server](guides/serve.md) for detailed setup.

### Basic Usage

```bash
mcp-stdio serve [OPTIONS] -- COMMAND [ARGS...]

Arguments:
  COMMAND [ARGS...]    Backend command to spawn (e.g., python -m my_mcp_server)
```

### Server Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--host HOST` | `127.0.0.1` | Bind address |
| `--port PORT` | `8080` | Bind port |
| `--path PATH` | `/mcp` | HTTP endpoint path |

### Authentication

| Flag | Environment Variable | Description |
|------|----------------------|-------------|
| `--auth-token TOKEN` | `MCP_STDIO_SERVE_TOKEN` | Static bearer token (acts as OAuth Resource Server; optional) |
| `--enable-oauth` | — | Enable embedded OAuth 2.1 Authorization Server (PKCE auth-code, DCR, refresh) |
| `--public-url URL` | — | Public HTTPS URL pinning the issuer and well-known documents (strongly recommended behind a reverse proxy; serve still starts without it) |
| `--trusted-user-header HEADER` | — | HTTP header name containing the authenticated user (trusted only because the fronting proxy strips client-supplied copies) |
| `--dev-user USER` | — | **Insecure, testing only.** Stand-in user identity for loopback testing without real SSO |
| `--access-token-ttl SECONDS` | `3600` | Access token lifetime in seconds |
| `--allow-redirect-uri URL` | — | Additional redirect URI to trust for Dynamic Client Registration (repeatable; e.g., `https://claude.ai/api/mcp/auth_callback` for web-based clients) |
| `--token-store PATH` | — | Path to persist issued tokens, registrations, and replay tombstones. Survives restarts so clients retain valid tokens. Each serve process must have its own path. File is created `0600`; treat like a private key |

### Session Management

| Flag | Default | Description |
|------|---------|-------------|
| `--max-sessions N` | `100` | Maximum concurrent sessions; an initialize past the cap gets `503` |
| `--session-idle-ttl SECONDS` | `0` (disabled) | Idle timeout for OLDER clients' sessions (newer clients have `--modern-idle-ttl`); evict a session and its child after this much inactivity so a client that disconnects without DELETE does not pin a slot |
| `--max-sessions-per-owner N` | `0` (disabled) | On a new initialize, LRU-evict that OAuth user's older sessions down to `N`, reclaiming ghosts left by a client that reconnects without DELETE; static-token and open-gateway sessions are exempt |

<a id="modern-era-serve"></a>

### Newer MCP clients (2026-07-28)

Nothing to turn on — `serve` answers newer and older clients on the same
address automatically. These flags tune caching, tidy up idle backends,
and (if you want) drop older clients entirely.

| Flag | Default | Description |
|------|---------|-------------|
| `--cache-ttl-ms MS` | `60000` | How long (in milliseconds) a newer client may cache list-style results such as `tools/list`. `0` tells clients not to cache at all. Results are always marked private, never shared between users. Tool call results are never cached |
| `--modern-idle-ttl SECONDS` | `0` (off) | Shut down a backend serving newer clients after this long with no request, freeing the process. Safe to set aggressively — those clients keep no state, so they just get a fresh backend next time. A backend that is mid-request is never shut down. Separate from `--session-idle-ttl`, which governs older clients |
| `--modern-only` | off | Serve **only** newer clients. Older ones are turned away instead of being given a session: `GET` and `DELETE` answer `405`, and an older client's `initialize` gets an error naming the version this endpoint does serve. OAuth discovery endpoints keep working, so login still bootstraps |

Newer clients can also open a long-lived connection to hear when your
server's tool, prompt or resource lists change — see
[Telling clients your lists changed](modes.md#listchanged-serve).
There is no flag for it. A client may hold up to **four** such
connections per authenticated user; a fifth is refused rather than
queued. Each one sends a comment every 15 seconds so proxies do not time
it out, and a backend with a connection attached is never reclaimed by
`--modern-idle-ttl`.

Note that `--modern-idle-ttl` counts from the last *request*, and a
long-lived connection is one request that never finishes — so a user who
keeps one open keeps their backend alive, which is the intent.


---

## Standards Conformance

mcp-stdio implements the following specifications:

### MCP (Model Context Protocol)

- Streamable HTTP transport (current, spec rev 2025-06-18) — negotiated `MCP-Protocol-Version` is captured from `initialize` and sent on every subsequent request
- Streamable HTTP transport, spec rev **2026-07-28** — capability discovery, per-request metadata and headers, session-less requests, cache hints on list results, the long-lived notification connection (both as a client and, for the listChanged notifications, in `serve`), and mid-call requests back to the client. Opt in with `--protocol-era`; `serve` answers both revisions on one endpoint. Interoperability verified against python-sdk v2.0.0 in both directions
- SSE transport (legacy, MCP 2024-11-05)
- Client ID Metadata Documents (MCP 2025-11-25 draft extension) — see the OAuth section below

### OAuth 2.1 & OpenID Connect

- [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) Protected Resource Metadata
  - §3 discovery of authorization servers via `/.well-known/oauth-protected-resource`
  - §3.1 path-aware well-known URL construction (for path-based reverse-proxy deployments)
  - §3.3 resource field validation
  - §5.1 `WWW-Authenticate: Bearer resource_metadata=` hint

- [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) Authorization Server Metadata
  - §3.1 well-known URL construction, including path insertion for issuers with path components
  - §3.3 issuer validation (cross-origin guard, same-origin mismatch warnings)
  - §3 OpenID Connect Discovery 1.0 fallback

- [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) Resource Indicators
  - §2 resource parameter in authorization, token exchange, **and refresh** requests

- [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) PKCE
  - §4.1–4.2 S256 code_challenge_method with 86-char code_verifier

- [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) Device Authorization Grant
  - §3.1 device authorization request with resource indicator
  - §3.4–3.5 token polling with authorization_pending, slow_down, expired_token, and access_denied handling

- [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) Dynamic Client Registration
  - §3 client registration request; token_endpoint_auth_method chosen from AS metadata
  - §3.2.1 client_secret_expires_at handling (auto re-register on expiry)
  - application_type: "native" per RFC 8252 §8.4

- [Client ID Metadata Documents](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#client-id-metadata-documents)
  - MCP 2025-11-25 / draft-ietf-oauth-client-id-metadata-document-00
  - --client-metadata-url presents an operator-hosted HTTPS document as client_id

- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) OAuth 2.0
  - §2.3.1 client_secret_basic (Authorization header with percent-encoded credentials)

- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) Bearer Token Usage
  - §2.1 Authorization: Bearer request header

### HTTP & Resilience

- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) HTTP Semantics
  - §10.2.3 `Retry-After` header parsing (delta-seconds and HTTP-date formats; formerly RFC 7231 §7.1.3)

- HTTP 429 (Too Many Requests) and 503 (Service Unavailable) — honors Retry-After up to 60 seconds

- Automatic retry with exponential backoff on connection errors (up to 3 retries)

### WHATWG Server-Sent Events

- [Server-Sent Events Standard](https://html.spec.whatwg.org/multipage/server-sent-events.html)
  - SSE parser for legacy MCP servers

---

## Known Limitations

See [WORKAROUNDS.md](https://github.com/shigechika/mcp-stdio/blob/main/WORKAROUNDS.md) for known issues in:

- Claude Code's HTTP transport
- mcp-remote (TypeScript MCP client)
- MCP SDKs (TypeScript & Python)
- Windows stdio handling

mcp-stdio works around these issues at the wire level where possible.

---

## File Locations

| Component | Location | Permissions |
|-----------|----------|-------------|
| OAuth token cache | `~/.config/mcp-stdio/tokens.json` | `0600` |
| Serve mode token store | (user-specified via `--token-store`) | `0600` |

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `MCP_BEARER_TOKEN` | Static bearer token for client mode |
| `MCP_OAUTH_CLIENT_ID` | Pre-registered OAuth client ID |
| `MCP_OAUTH_REFRESH_LEEWAY` | Seconds before token expiry to trigger refresh (default: 60) |
| `MCP_STDIO_SERVE_TOKEN` | Static bearer token for serve mode |
| `MCP_STDIO_MRTR_STRIP` | Set to `1` to stop advertising the client's `sampling` / `elicitation` / `roots` capabilities to a modern-era remote, withdrawing its invitation to use the multi round-trip requests (MRTR) pattern. Escape hatch only — the relay bridges MRTR by default, and a server that sends it anyway is still bridged. |
| `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` | Standard proxy configuration |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Runtime error (connection failure, OAuth authentication failure, misconfiguration detected at startup) |
| `2` | Invalid command-line arguments (standard `argparse` usage error) |
| `130` | Interrupted (Ctrl-C / `SIGINT`) |

---

## Logging

- All diagnostics are written to stderr. The relay's own connection/retry/reconnect messages are prefixed `[mcp-stdio]`; startup and OAuth error/warning messages print as bare `error: ...` / `warning: ...` lines instead
- There is currently no separate verbose/debug logging mode — the stderr output above is all there is
