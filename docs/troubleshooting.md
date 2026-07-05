# Troubleshooting

Common issues and how to resolve them. For the full list of known workarounds in Claude Code, mcp-remote, and the MCP SDKs, see [WORKAROUNDS.md](https://github.com/shigechika/mcp-stdio/blob/main/WORKAROUNDS.md).

## Connection issues

### Browser never opens for OAuth login

**Problem:** You ran `mcp-stdio --oauth` but no browser window appeared.

**Solution:**
1. Check stderr — mcp-stdio always prints the authorization URL there, whether or not the browser opened automatically.
2. Copy and paste that URL into your browser manually.
3. Complete the login flow; the authorization code is captured on the loopback callback.

### `401 Unauthorized` — "Worked yesterday, broken today"

**Problem:** The connection worked fine, but today you get a `401` error.

**Cause:** The server may have rotated its keys or revoked the grant.

**Solution:**
Delete the cached token and re-authorize:

```bash
rm ~/.config/mcp-stdio/tokens.json
```

Then run your client again. On first use, a browser window opens for login; after that, tokens are cached and refreshed automatically.

### Repeated "Connection expired" prompts despite a valid refresh token

**Problem:** Your MCP client keeps reporting the connection as expired, even though `mcp-stdio` holds a working refresh token.

**Cause:** By default `mcp-stdio` refreshes the access token proactively, shortly before it expires (`--oauth-refresh-leeway`, default 60 s) — but this only helps if your MCP client actually reuses the connection through `mcp-stdio`.

**Solution:**
1. Make sure you are not passing `--no-proactive-refresh` (proactive refresh is on by default).
2. If the server signals expiry with an HTTP 200 response and a tool-result error instead of a transport `401` (e.g. some enterprise MCP gateways), mcp-stdio may not detect it reactively — proactive refresh is the primary defense here; if you still see stale sessions, please [file an issue](https://github.com/shigechika/mcp-stdio/issues/new) with the gateway's behavior (see [shigechika/mcp-stdio#242](https://github.com/shigechika/mcp-stdio/issues/242) for the original report of this class of gateway).
3. If your server does not send `expires_in` at all, set the leeway explicitly:
   ```bash
   mcp-stdio --oauth --oauth-refresh-leeway 300 https://your-server.example.com/mcp
   ```

Some MCP clients have their own history of not re-invoking their auth header callback when a token expires mid-session (see Claude Code [#53267](https://github.com/anthropics/claude-code/issues/53267) and [#65036](https://github.com/anthropics/claude-code/issues/65036)) — this is exactly the class of problem mcp-stdio's proactive/reactive refresh is designed to route around, since mcp-stdio (not your MCP client) owns the token lifecycle end to end.

### `AADSTS9010010` on Microsoft Entra ID

**Problem:** Authorization fails with `AADSTS9010010` ("audience validation failed") when connecting through Microsoft Entra ID with `api://` scopes.

**Cause:** Some Entra ID configurations reject the RFC 8707 `resource` parameter outright.

**Solution:**
```bash
mcp-stdio --oauth --no-resource-indicator https://your-server.example.com/mcp
```

This omits the `resource` parameter from every OAuth request (authorization, token exchange, refresh, and device flow).

## Tool and resource issues

### Tools beyond the first page are invisible

**Problem:** You have dozens of tools defined, but your client only sees the first ~20.

**Cause:** Claude Code sends only the first `tools/list` request and silently discards `nextCursor`, so tools on page 2+ never reach the client.

**Solution:**
Nothing to configure — mcp-stdio already follows `nextCursor` transparently across `tools/list`, `resources/list`, `resources/templates/list`, and `prompts/list` on the Streamable HTTP transport, merging every page into a single response before it reaches your client. This does **not** apply to `--transport sse` (legacy transport, not auto-paginated); keep your tool count under one page there.

See Claude Code [#39586](https://github.com/anthropics/claude-code/issues/39586).

### `tools/list` fails with "Invalid session ID" right after a successful connect

**Problem:** The connection shows as established and `initialize` succeeds, but a subsequent `tools/list` or tool call is rejected by the server as an invalid or missing session.

**Cause:** Some MCP clients (including some Claude Code versions) do not echo the `Mcp-Session-Id` header returned by `initialize` on later requests, so session-aware servers (e.g. mcp-grafana, mcp-go) reject them.

**Solution:**
Nothing to configure — mcp-stdio captures `Mcp-Session-Id` from the `initialize` response itself and injects it on every subsequent request, regardless of what your MCP client does. If you still see this, the session may have genuinely expired server-side; restart your client to force a fresh `initialize`.

See Claude Code [#70386](https://github.com/anthropics/claude-code/issues/70386).

### Tools disappear after a brief network drop or reconnect

**Problem:** Tools were listed fine, but after a short disconnect / reconnect they stop working or vanish from the list.

**Cause:** The MCP session was lost (e.g., the backend server restarted, or the connection was interrupted); some Claude Code versions have also had regressions in Streamable HTTP reconnection handling.

**Solution:**
1. mcp-stdio automatically re-initializes the session on a `404` "session not found" response from the server.
2. If tools remain unavailable, restart your MCP client (Claude Desktop / Claude Code) to force a fresh session.

See Claude Code [#34498](https://github.com/anthropics/claude-code/issues/34498), [#38631](https://github.com/anthropics/claude-code/issues/38631).

## Authentication issues

### Static bearer token not being sent

**Problem:** You set `--bearer-token` or `MCP_BEARER_TOKEN`, but the server reports it as missing or invalid.

**Cause:** mcp-stdio attaches the token to the `Authorization` header on every outbound request; a rejection is more likely one of: an incorrect or expired token, or the server expecting the credential somewhere other than the `Authorization` header (e.g. a query parameter or custom header).

**Solution:**
1. Verify your token is correct and not expired.
2. Check the server's authentication docs to confirm it expects an `Authorization: Bearer` header — if it expects a different header, pass it explicitly with `-H 'Header-Name: value'`.
3. Run mcp-stdio in the foreground and check stderr; connection and retry diagnostics are printed there.

### OAuth scope not being honored

**Problem:** You request a scope with `--oauth-scope`, but the server still complains about insufficient scope.

**Cause:** The authorization server may have rejected your requested scope and granted a smaller one.

**Solution:**
1. Check the authorization server's own logs or admin console for the scope it actually granted; mcp-stdio does not currently print the granted scope itself.
2. If the server downgraded your scope, check the authorization server's policy or contact the server operator.
3. Some servers support **step-up authorization**: if a tool call needs a broader scope, the server returns `403 insufficient_scope` with the required scopes listed, and mcp-stdio automatically re-authorizes for the union of the granted and required scopes (RFC 9470), then retries the call. Note that some MCP clients do not automatically retry a tool call after mcp-stdio completes a step-up in the background (Claude Code [#44652](https://github.com/anthropics/claude-code/issues/44652)) — if the call still reports an error, try it again once.

## Transport issues

### Connection timeout or slow responses

**Problem:** Requests hang or time out frequently.

**Cause:** Network latency, proxy misconfiguration, or the server is slow.

**Solution:**
1. Increase the read timeout:
   ```bash
   mcp-stdio --timeout-read 300 https://your-server.example.com/mcp
   ```
2. mcp-stdio honors standard proxy env vars:
   ```bash
   HTTPS_PROXY=http://proxy.example.com:8080 mcp-stdio --oauth https://your-server.example.com/mcp
   ```
   (`NO_PROXY` is respected too — this is a case where using mcp-stdio's own HTTP client sidesteps a bug in some other MCP clients' built-in transports; see Claude Code [#34804](https://github.com/anthropics/claude-code/issues/34804).)
3. Test connectivity manually:
   ```bash
   curl -v https://your-server.example.com/mcp
   ```

### `Connection reset by peer` or `SSL: CERTIFICATE_VERIFY_FAILED`

**Problem:** mcp-stdio cannot establish a connection to the server.

**Cause:** Either the server is not reachable, the TLS certificate is invalid, or a proxy is intercepting the connection.

**Solution:**
1. Verify the server URL and check connectivity:
   ```bash
   curl -v https://your-server.example.com/mcp
   ```
2. If curl works but mcp-stdio fails, run mcp-stdio in the foreground and check stderr for the underlying error.
3. If the certificate is self-signed and you trust the server:
   - On macOS: Add the cert to your system keychain.
   - On Linux: Set `SSL_CERT_FILE` env var pointing to your CA bundle.
   - On Windows: Import the cert into the Windows Certificate Store.

### SSE stream drops mid-request

**Problem:** You are using a legacy SSE server (`--transport sse`), and a tool call was in flight when the connection dropped.

**Cause:** The SSE GET stream disconnected while one or more requests were still awaiting their reply.

**Solution:**
Nothing to configure — mcp-stdio reconnects automatically and synthesizes a JSON-RPC error ("SSE stream disconnected before response arrived; please retry") for every request that was in flight when the stream dropped, instead of leaving your client hanging forever. Just retry the call once you see the error. This mirrors the failure mode reported in Claude Code [#60061](https://github.com/anthropics/claude-code/issues/60061); if possible, prefer upgrading the server to Streamable HTTP (the current MCP spec), which does not have this failure mode at all.

## Headless / SSH environment

### Cannot open browser for OAuth login in SSH or CI

**Problem:** You are on an SSH box or in a CI environment with no display, and `--oauth` cannot open a browser.

**Solution:**
Use the Device Authorization Grant (RFC 8628) instead:

```bash
mcp-stdio --oauth-device https://your-server.example.com/mcp
```

This prints a user code (e.g., `ABCD-1234`). Open it in your browser on any device and confirm. After that, mcp-stdio completes the OAuth flow on the SSH box without needing a local display.

## Still stuck?

1. Run mcp-stdio with `--check` to validate connectivity before adding it to your client config:
   ```bash
   mcp-stdio --check --oauth https://your-server.example.com/mcp
   ```
2. Check stderr for detailed error messages.
3. Search [GitHub Issues](https://github.com/shigechika/mcp-stdio/issues) for your error.
4. If all else fails, [file an issue](https://github.com/shigechika/mcp-stdio/issues/new) with the full command and error output.
