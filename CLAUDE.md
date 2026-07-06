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

Uses **hatchling** as the build backend (`build-backend = "hatchling.build"` in `pyproject.toml`). Version is defined in `src/mcp_stdio/__init__.py` (`__version__`).

## Architecture

A bidirectional stdio ↔ HTTP gateway for MCP (Model Context Protocol) servers — translates between stdio JSON-RPC framing and MCP HTTP transports (Streamable HTTP and legacy SSE). Supports both client mode (relaying requests to remote servers) and server mode (exposing local servers over HTTP). Minimal runtime dependencies.

Four modules under `src/mcp_stdio/`:

- **`relay.py`** — Two transport implementations sharing stdin/stdout plumbing (file name kept for import compatibility):
  - `run()` — Streamable HTTP transport (MCP current spec, default). Reads JSON-RPC from stdin line-by-line, streams POST to the remote URL via httpx, parses JSON or SSE responses, writes to stdout
  - `run_sse()` — SSE transport (MCP 2024-11-05 legacy). Spawns a daemon reader thread that maintains a long-lived `GET /sse` connection, parses `endpoint`/`message` events per the WHATWG SSE spec, writes to stdout
  - Both paths enforce the MCP cancellation spec's receiver-side SHOULD (and shield the client from canceller-side bugs) via a shared `_CancelTracker` + `_emit` gate: ids seen in `notifications/cancelled` are tracked and late responses are dropped before reaching the client
  - Signal handlers (`signal.signal`) are set from the main thread only — the SSE reader runs in a daemon thread so pytest tests must drive `run_sse` from the main thread
- **`cli.py`** — argparse-based CLI for client mode. Builds headers, resolves `MCP_BEARER_TOKEN` / `MCP_OAUTH_CLIENT_ID` env vars, runs the OAuth flow before relay if `--oauth` or `--oauth-device` is set, dispatches to `relay.run()` or `relay.run_sse()` based on `--transport`
- **`serve_cli.py`** — argparse-based CLI for server mode. Spawns a local stdio MCP server as a child process and exposes it over HTTP with optional Bearer token or embedded OAuth 2.1 AS; supports multi-session isolation and per-user binding when OAuth is enabled
- **`serve.py`** — HTTP server (stdlib `http.server`). Implements Streamable HTTP request/response semantics, session management (`Mcp-Session-Id`), per-session child process spawning, optional Bearer token validation, and embedded OAuth 2.1 AS (PKCE, DCR, refresh, RFC 9728 Protected Resource Metadata, RFC 8707 resource indicators, RFC 9207 iss parameter)
- **`oauth.py`** — OAuth 2.1 client: RFC 9728/8414 discovery, RFC 7591 dynamic client registration, RFC 7636 PKCE, RFC 8707 resource indicators, authorization code flow with localhost callback support, RFC 8628 device authorization grant, token refresh, and proactive refresh
- **`token_store.py`** — Token persistence in `~/.config/mcp-stdio/tokens.json` (0o600). Stores per-server-URL tokens with client credentials and endpoint URLs for refresh. Migrates legacy `~/.mcp-stdio/tokens.json`

Entry point: `mcp-stdio` command → `mcp_stdio.cli:main` (client mode) or `mcp-stdio serve` → `mcp_stdio.serve_cli:main` (server mode).

## Release

Releases are driven by **release-please** (Conventional Commits) — do not tag `v*` by hand. Pushing commits to `main` updates a standing "release PR" that bumps `__version__` (`src/mcp_stdio/__init__.py`) and generates a changelog entry.
