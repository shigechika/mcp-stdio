# Connect to a remote MCP server

Goal: a remote HTTP MCP server appears in Claude Desktop or Claude Code as
if it were a local one — login handled, tokens refreshed, transport quirks
absorbed.

## 1. Check the connection first

Before touching any client config, verify mcp-stdio can reach the server:

```bash
mcp-stdio --check --oauth https://mcp.example.com/mcp
```

`--check` runs the whole path once — discovery, OAuth login in your
browser, token exchange, an MCP `initialize` round-trip — and prints what
happened. If this succeeds, the client config below will work.

No OAuth on the server? Drop `--oauth`. Static token instead? Use
`MCP_BEARER_TOKEN` (see [Variations](#variations)).

## 2. Add it to your client

=== "Claude Desktop"

    `claude_desktop_config.json`:

    ```json
    {
      "mcpServers": {
        "my-remote-server": {
          "command": "mcp-stdio",
          "args": ["--oauth", "https://mcp.example.com/mcp"]
        }
      }
    }
    ```

=== "Claude Code"

    ```bash
    claude mcp add my-remote-server -- mcp-stdio --oauth https://mcp.example.com/mcp
    ```

Restart the client. On the first request a browser window opens for the
server's login page; after that, tokens live in
`~/.config/mcp-stdio/tokens.json` (file mode `0600`) and are shared by every
terminal and session — you will not log in again until the refresh token
itself expires or is revoked.

## What you get without asking

- **Automatic token refresh** — reactively on `401`, and proactively in the
  background shortly before expiry, so long sessions do not die at the
  access token's TTL.
- **Session recovery** — an expired MCP session (`404`) is re-initialized
  transparently.
- **Client-bug shielding** — cancellation races, pagination, `Retry-After`,
  and other cross-implementation gaps are absorbed in the middle; see
  [WORKAROUNDS](https://github.com/shigechika/mcp-stdio/blob/main/WORKAROUNDS.md)
  for the catalogue.

## Variations

| You need… | Do this |
|---|---|
| Static bearer token, no OAuth | `MCP_BEARER_TOKEN=… mcp-stdio https://…/mcp` |
| Extra scopes | `--oauth-scope "openid offline_access mcp:tools"` |
| No browser on this machine (SSH box, container) | `--oauth-device` — see [Headless login](device-flow.md) |
| The server insists on the OIDC `id_token` (Google IAP, AWS) | `--oauth-use-id-token` |
| Legacy SSE server (2024-11-05 transport) | `--transport sse` |
| Corporate proxy | honored via standard `HTTPS_PROXY` / `NO_PROXY` env vars |

Every flag: `mcp-stdio --help`, or the
[README](https://github.com/shigechika/mcp-stdio#readme).

## Troubleshooting quickies

- **Browser never opens** — the authorize URL is printed to stderr; open it
  manually (the client's MCP log shows it).
- **`AADSTS9010010` on Microsoft Entra ID** — some Entra ID configurations
  reject the `resource` parameter outright; add `--no-resource-indicator`.
  See [Troubleshooting](../troubleshooting.md#aadsts9010010-on-microsoft-entra-id).
- **Worked yesterday, `401` today** — the server may have rotated its keys or
  revoked the grant. Delete the server's entry from
  `~/.config/mcp-stdio/tokens.json` and let it re-authorize.
