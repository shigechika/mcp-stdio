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
| `--oauth-scope SCOPE` | — | OAuth scope to request (repeatable) |
| `--oauth-use-id-token` | — | Present the OIDC id_token as the Bearer credential instead of access_token (AWS Bedrock / Cognito) |
| `--oauth-eager` | — | Cold-start: answer initialize locally and run interactive OAuth in the background, so a long login does not exceed the client's ~60 s timeout |
| `--oauth-refresh-leeway SECONDS` | `MCP_OAUTH_REFRESH_LEEWAY` | Proactively refresh tokens this many seconds before expiry (default: 60) |
| `--no-proactive-refresh` | — | Disable the background timer that refreshes the OAuth token before it expires |
| `--oauth-timeout SECONDS` | — | Seconds to wait for the interactive OAuth flow (browser callback / device-code confirmation) before giving up (default: 120) |
| `--no-resource-indicator` | — | Omit the RFC 8707 resource parameter from all OAuth requests. Required for some authorization servers that reject it (e.g. Microsoft Entra ID with api:// scopes) |

### Transport

| Flag | Default | Description |
|------|---------|-------------|
| `--transport {streamable-http,sse}` | `streamable-http` | Transport type (Streamable HTTP is current MCP spec; SSE is legacy 2024-11-05) |
| `--timeout-connect SEC` | 10 | Connection timeout in seconds |
| `--timeout-read SEC` | 120 | Read timeout in seconds |
| `--sse-read-timeout SEC` | 300 | Idle read timeout on the SSE GET stream (SSE transport only; 0 disables) |
| `--no-tcp-keepalive` | — | Disable TCP keepalive on the HTTP socket |

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
| `--public-url URL` | — | Public HTTPS URL pinning the issuer and well-known documents (required when behind a reverse proxy) |
| `--trusted-user-header HEADER` | — | HTTP header name containing the authenticated user (trusted only because the fronting proxy strips client-supplied copies) |
| `--dev-user USER` | — | **Insecure, testing only.** Stand-in user identity for loopback testing without real SSO |
| `--access-token-ttl SECONDS` | `3600` | Access token lifetime in seconds |
| `--allow-redirect-uri URL` | — | Additional redirect URI to trust for Dynamic Client Registration (repeatable; e.g., `https://claude.ai/api/mcp/auth_callback` for web-based clients) |
| `--token-store PATH` | — | Path to persist issued tokens, registrations, and replay tombstones. Survives restarts so clients retain valid tokens. Each serve process must have its own path. File is created `0600`; treat like a private key |

### Session Management

| Flag | Default | Description |
|------|---------|-------------|
| `--max-sessions N` | `100` | Maximum concurrent sessions; an initialize past the cap gets `503` |
| `--session-idle-ttl SECONDS` | `0` (disabled) | Idle timeout; evict a session and its child after this much inactivity so a client that disconnects without DELETE does not pin a slot |

---

## Standards Conformance

mcp-stdio implements the following specifications:

### MCP (Model Context Protocol)

- [MCP 2025-11-25 Specification](https://modelcontextprotocol.io/specification/2025-11-25/)
  - Streamable HTTP transport (current)
  - SSE transport (legacy, MCP 2024-11-05)
  - Authorization spec

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

- [RFC 7230](https://www.rfc-editor.org/rfc/rfc7230) HTTP/1.1 Message Syntax and Routing
  - Retry-After header parsing (delta-seconds and HTTP-date formats)

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
| `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` | Standard proxy configuration |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (invalid arguments, connection failure, etc.) |
| `2` | OAuth timeout or user cancelled |

---

## Logging

- All errors and diagnostics are written to stderr
- Requests to the remote server are logged with query strings redacted
- Token exchange details are logged in verbose output
