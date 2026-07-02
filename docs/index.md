# mcp-stdio

A minimal stdio-to-HTTP gateway for MCP (Model Context Protocol) servers.
One small Python package, one runtime dependency (`httpx`), two jobs:

- **Connect** an MCP client that only speaks stdio (Claude Desktop, Claude
  Code, …) to a **remote HTTP MCP server** — including the OAuth 2.1 login,
  token storage, and refresh.
- **Publish** a local stdio MCP server as a **Streamable HTTP endpoint** with
  a built-in OAuth 2.1 authorization server — multi-user, session-isolated.

Not sure which one you need? Start with
[Two ways to use it](modes.md).

## Install

```bash
# Homebrew
brew install shigechika/tap/mcp-stdio

# or PyPI
pip install mcp-stdio

# or run without installing
uvx mcp-stdio --help
```

## 30-second quickstart

Connect Claude Desktop to a remote MCP server that requires OAuth login —
add this to `claude_desktop_config.json`:

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

On first use a browser window opens for login; tokens are cached in
`~/.config/mcp-stdio/tokens.json` and refreshed automatically from then on.

That is the *client* side. To go the other direction — publish your own
stdio MCP server over HTTPS — see
[Publish your stdio server](guides/serve.md).

## Why this exists

MCP clients and servers disagree about transports and cut corners around
OAuth in ways that break real deployments. mcp-stdio sits in the middle and
absorbs those differences: it follows the MCP spec and the OAuth RFCs
closely, works around
[known issues in popular clients](https://github.com/shigechika/mcp-stdio/blob/main/WORKAROUNDS.md),
and stays small enough to audit.

For the full feature list and standards conformance, see the
[README](https://github.com/shigechika/mcp-stdio#readme).
