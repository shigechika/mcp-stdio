# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Language Policy (Public Repository)

- Code comments, commit messages, documentation, and PR descriptions: **English**
- README.md in English; README.ja.md in Japanese

## Build & Test

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run a single test file or class
pytest tests/test_relay.py -v
pytest tests/test_relay.py::TestSendRequest -v

# Build package
pip install build && python -m build
```

Uses **hatch** as the build backend. Version is defined in `src/mcp_stdio/__init__.py` (`__version__`).

## Architecture

A minimal stdio-to-HTTP relay for MCP (Model Context Protocol) servers. Only runtime dependency is **httpx**.

Four modules under `src/mcp_stdio/`:

- **`relay.py`** — Core loop: reads JSON-RPC from stdin line-by-line, streams POST to the remote URL via httpx, parses JSON or SSE responses, writes to stdout. Handles retry with backoff (3 attempts), session ID tracking (`Mcp-Session-Id` header), 404-based session recovery, and 401-based token refresh.
- **`cli.py`** — argparse-based CLI. Builds headers, resolves `MCP_BEARER_TOKEN` / `MCP_OAUTH_CLIENT_ID` env vars, runs OAuth flow before relay if `--oauth` is set, and calls `relay.run()`.
- **`oauth.py`** — OAuth 2.1 client: RFC 9728/8414 discovery, RFC 7591 dynamic client registration, RFC 7636 PKCE, RFC 8707 resource indicators, authorization code flow with localhost callback server, token exchange and refresh.
- **`token_store.py`** — Token persistence in `~/.mcp-stdio/tokens.json` (0o600). Stores per-server-URL tokens with client credentials and endpoint URLs for refresh.

Entry point: `mcp-stdio` command → `mcp_stdio.cli:main`.

## Release

Tagging `v*` triggers the GitHub Actions release pipeline: test → build → TestPyPI → PyPI → MCP Registry → GitHub Release → Homebrew tap update. The `server.json` version is patched from the git tag at publish time.
