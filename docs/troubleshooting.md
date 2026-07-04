# Troubleshooting

Common issues and how to resolve them. For the full list of known workarounds in Claude Code, mcp-remote, and the MCP SDKs, see [WORKAROUNDS.md](https://github.com/shigechika/mcp-stdio/blob/main/WORKAROUNDS.md).

## Connection issues

### Browser never opens for OAuth login

**Problem:** You ran `mcp-stdio --oauth` but no browser window appeared.

**Solution:**
1. Check stderr for the authorization URL — it's printed there if the browser cannot open automatically.
2. Copy and paste that URL into your browser manually.
3. Complete the login flow; the authorization code is captured on the loopback callback.

See Claude Code [#28293](https://github.com/anthropics/claude-code/issues/28293).

### Login loops or AADSTS errors on Microsoft Entra ID

**Problem:** You see repeated login prompts or errors like `AADSTS9010010` when connecting to a server on Microsoft Entra ID.

**Solution:**
Set an explicit OAuth scope that includes `openid` and `offline_access`:

```bash
mcp-stdio --oauth --oauth-scope "openid offline_access" https://your-server.example.com/mcp
```

Different Entra ID tenants require different scopes. Check your server's documentation or the error message for the exact scope.

See Claude Code [#39271](https://github.com/anthropics/claude-code/issues/39271).

### `401 Unauthorized` — "Worked yesterday, broken today"

**Problem:** The connection worked fine, but today you get a `401` error.

**Cause:** The server may have rotated its keys or revoked the grant.

**Solution:**
Delete the cached token and re-authorize:

```bash
rm ~/.config/mcp-stdio/tokens.json
```

Then run your client again. On first use, a browser window opens for login; after that, tokens are cached and refreshed automatically.

### Connection expires after 24 hours or at a fixed time

**Problem:** The connection dies at the same time each day, even if you're actively using it.

**Cause:** Your OAuth access token expires and mcp-stdio is not refreshing it proactively.

**Solution:**
If you are using mcp-stdio in a long-lived session (e.g., Claude Code running all day), mcp-stdio should refresh the token shortly before it expires. If it is not:

1. Make sure you are not passing `--no-proactive-refresh` (default is to refresh proactively).
2. Check that the server's token response includes an `expires_in` field (or `exp` in the JWT).
3. If the server does not send `expires_in`, manually set the refresh leeway:

```bash
mcp-stdio --oauth --oauth-refresh-leeway 300 https://your-server.example.com/mcp
```

This refreshes 5 minutes before expiry instead of the default 60 seconds.

See Claude Code [#242](https://github.com/anthropics/claude-code/issues/242).

## Tool and resource issues

### Tools silently vanish after connecting

**Problem:** You connect successfully, tools are listed, but then they disappear.

**Cause:** Most likely one of two things:
1. The MCP session was lost (e.g., the server restarted); mcp-stdio recovers it on the next request but tools are not re-listed until you restart your client.
2. Claude Code did not send the `Mcp-Session-Id` header on a subsequent request (see issue below).

**Solution:**
1. Restart your MCP client (Claude Desktop / Claude Code).
2. If it happens repeatedly, check the server logs for session drops.

See Claude Code [#34498](https://github.com/anthropics/claude-code/issues/34498).

### `404` on tool calls after a tool was listed

**Problem:** A tool appeared in the list but calling it returns `404`.

**Cause:** Claude Code is not echoing the `Mcp-Session-Id` header on tool calls, so the server cannot find the session.

**Solution:**
This is a Claude Code bug. mcp-stdio cannot work around it. Restart Claude Code to re-sync the session.

See Claude Code [#34008](https://github.com/anthropics/claude-code/issues/34008).

### Tools beyond the first page are invisible

**Problem:** You have dozens of tools defined, but your client only sees the first ~20.

**Cause:** Claude Code ignores pagination on `tools/list` and `resources/list`, only fetching the first page. If your MCP server uses `nextCursor`, tools on page 2+ are lost.

**Solution:**
This is a limitation of Claude Code's HTTP transport. mcp-stdio cannot work around it on the client side. The workaround is to keep the total number of tools under one page.

See Claude Code [#42470](https://github.com/anthropics/claude-code/issues/42470).

## Authentication issues

### Static bearer token not being sent

**Problem:** You set `--bearer-token` or `MCP_BEARER_TOKEN`, but the server reports it as missing or invalid.

**Cause:** Unlikely — mcp-stdio adds the token to every request. More likely the server is looking for the token in the wrong place (e.g., a query parameter instead of the `Authorization` header).

**Solution:**
1. Enable verbose logging by running mcp-stdio in the foreground and checking stderr for the requests being sent.
2. Verify your token is correct and not expired.
3. Check the server's authentication docs to confirm it expects an `Authorization: Bearer` header.

### OAuth scope not being honored

**Problem:** You request a scope with `--oauth-scope`, but the server still complains about insufficient scope.

**Cause:** The authorization server may have rejected your requested scope and granted a smaller one.

**Solution:**
1. Check what scope was actually granted. Look for the `scope` field in the server's token response (printed in mcp-stdio's logs if verbose).
2. If the server downgraded your scope, check the authorization server's policy or contact the server operator.
3. Some servers support **step-up authorization** — if a tool requires a broader scope, it returns `403 insufficient_scope` with the required scopes listed. mcp-stdio re-authorizes automatically for the union of granted and required scopes.

## Transport issues

### Connection timeout or slow responses

**Problem:** Requests hang or time out frequently.

**Cause:** Network latency, proxy misconfiguration, or the server is slow.

**Solution:**
1. Increase the read timeout:
   ```bash
   mcp-stdio --timeout-read 300 https://your-server.example.com/mcp
   ```
2. Check if you are behind a corporate proxy and set proxy env vars:
   ```bash
   HTTPS_PROXY=http://proxy.example.com:8080 mcp-stdio --oauth https://your-server.example.com/mcp
   ```
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
2. If curl works but mcp-stdio fails, enable debug logging in mcp-stdio (check stderr).
3. If the certificate is self-signed and you trust the server:
   - On macOS: Add the cert to your system keychain.
   - On Linux: Set `SSL_CERT_FILE` env var pointing to your CA bundle.
   - On Windows: Import the cert into the Windows Certificate Store.

### SSE stream drops mid-request

**Problem:** You are using a legacy SSE server (`--transport sse`), and long tool calls hang forever.

**Cause:** The SSE GET stream dropped mid-reply, and the client never received the response.

**Solution:**
mcp-stdio automatically reconnects on disconnect, but in-flight requests are lost. This is a limitation of the SSE transport. If possible, upgrade the server to use Streamable HTTP (the current MCP spec).

## Headless / SSH environment

### Cannot open browser for OAuth login in SSH or CI

**Problem:** You are on an SSH box or in a CI environment with no display, and `--oauth` cannot open a browser.

**Solution:**
Use the Device Authorization Grant (RFC 8628) instead:

```bash
mcp-stdio --oauth-device https://your-server.example.com/mcp
```

This prints a user code (e.g., `ABCD-1234`). Open it in your browser on any device and confirm. After that, mcp-stdio completes the OAuth flow on the SSH box without needing a local display.

See Claude Code [#34804](https://github.com/anthropics/claude-code/issues/34804).

## Still stuck?

1. Run mcp-stdio with `--check` to validate connectivity before adding it to your client config:
   ```bash
   mcp-stdio --check --oauth https://your-server.example.com/mcp
   ```
2. Check stderr for detailed error messages and issue references.
3. Search [GitHub Issues](https://github.com/shigechika/mcp-stdio/issues) for your error.
4. If all else fails, [file an issue](https://github.com/shigechika/mcp-stdio/issues/new) with the full command and error output.
