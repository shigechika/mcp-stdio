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
pytest tests/test_relay.py::TestWriteLine -v

# Integration harness against python-sdk v2, the 2026-07-28 reference peer
# (#367). Real localhost HTTP and a real relay subprocess, so it is a
# SEPARATE directory the unit gate never walks. Needs the extra; without it
# a conftest guard skips collection.
pip install -e ".[dev,integration]"
pytest tests_integration/ -v

# Build package
pip install build && python -m build
```

Uses **hatchling** as the build backend (`build-backend = "hatchling.build"` in `pyproject.toml`). Version is defined in `src/mcp_stdio/__init__.py` (`__version__`).

## Architecture

A gateway between stdio JSON-RPC framing and MCP's HTTP transports, in **both directions**:

- **relay** (the original job, `relay.py`) — the client side (stdin/stdout in, HTTP out): translates a local stdio MCP host to a remote Streamable HTTP or legacy SSE server.
- **serve** (`server.py`, `mcp-stdio serve`) — the mirror image, the server side (HTTP in, stdio out): publishes a locally-spawned stdio MCP server as a Streamable HTTP endpoint.

Only runtime dependency is **httpx** (the `serve` path is stdlib-only).

The substantive modules under `src/mcp_stdio/`:

- **`relay.py`** — Two transport implementations sharing stdin/stdout plumbing (file name kept for import compatibility):
  - `run()` — Streamable HTTP transport (MCP current spec, default). Reads JSON-RPC from stdin line-by-line, streams POST to the remote URL via httpx, parses JSON or SSE responses, writes to stdout. On the modern era (2026-07-28) a dedicated daemon reader thread owns stdin and feeds a FIFO queue, so a `notifications/cancelled` can abort the matching in-flight POST by closing its response stream; the legacy era keeps the literal synchronous stdin loop with zero threads. Handles retry with backoff (3 attempts), session ID tracking (`Mcp-Session-Id` header), 404-based session recovery, and 401-based token refresh.
  - `run_sse()` — SSE transport (MCP 2024-11-05 legacy). Spawns a daemon reader thread that maintains a long-lived `GET /sse` connection, parses `endpoint`/`message` events per the WHATWG SSE spec, and resolves the POST endpoint URL (possibly relative). The main thread reads stdin and POSTs to that endpoint. Auto-reconnects on stream disconnect, synthesizing a `-32000` error for every request whose reply was still in flight on the dropped stream (tracked in `_SseState.pending`, drained by `_drain_pending`; cancelled ids are skipped).
  - Both paths enforce the MCP cancellation spec's receiver-side SHOULD (and shield the client from canceller-side bugs) via a shared `_CancelTracker` + `_emit` gate: ids seen in `notifications/cancelled` on stdin are tracked with a 60 s TTL, and any late JSON-RPC response for a tracked id is dropped before it reaches stdout. Disable with `--no-cancel-filter`.
  - Signal handlers (`signal.signal`) are set from the main thread only — both transports now run daemon threads (`run_sse`'s SSE reader; `run()`'s modern-era listen/resource streams and stdin reader), so pytest tests must drive `run()` and `run_sse` from the main thread.
- **`cli.py`** — argparse-based CLI. Builds headers, resolves `MCP_BEARER_TOKEN` / `MCP_OAUTH_CLIENT_ID` env vars, runs the OAuth flow before relay if `--oauth` or `--oauth-device` is set, and dispatches to `run()` or `run_sse()` based on `--transport`.
- **`oauth.py`** — OAuth 2.1 client: RFC 9728/8414 discovery, RFC 7591 dynamic client registration, RFC 7636 PKCE, RFC 8707 resource indicators, authorization code flow with localhost callback server, RFC 8628 device authorization grant, RFC 9470 step-up authorization, token exchange and refresh.
- **`token_store.py`** — Token persistence in `~/.config/mcp-stdio/tokens.json` (0o600). Stores per-server-URL tokens with client credentials and endpoint URLs for refresh. Migrates legacy `~/.mcp-stdio/` tokens on first read.
- **`server.py`** — the `mcp-stdio serve` reverse gateway (dispatched from `cli.py` when `argv[1] == "serve"`). Spawns one backend stdio child process per MCP session (`SessionRegistry`, keyed on `Mcp-Session-Id`) and exposes them over a stdlib `http.server` Streamable HTTP endpoint (session minted on `initialize`, 404 on an unknown id, DELETE to terminate, GET SSE for server-initiated messages). Auth is optional and layered: open by default, `--auth-token` (or the `MCP_STDIO_SERVE_TOKEN` env var, preferred so the token isn't exposed in `ps`) for a static bearer, or `--enable-oauth` for an embedded OAuth 2.1 authorization server with optional `--token-store` persistence. Incoming `Host`/`X-Forwarded-Host` values are sanitized against `_HOST_ALLOWED` before they reach the `WWW-Authenticate` challenge / metadata responses. Stdlib only — adds no runtime dependency.

Entry point: `mcp-stdio` command → `mcp_stdio.cli:main` (which also dispatches `serve` to `server.py`).

## Release

Releases are driven by **release-please** (Conventional Commits) — do not tag `v*` by hand. Pushing commits to `main` updates a standing "release PR" that bumps `__version__` (`src/mcp_stdio/__init__.py`) and `CHANGELOG.md`. Merging that PR creates the `v*` tag and a GitHub Release (via a PAT so downstream workflows fire). The `release: published` event then runs the publish pipeline: test → build → TestPyPI → PyPI → MCP Registry → Homebrew tap update (jobs `test`/`build`/`testpypi`/`publish`/`mcp-registry`/`notify-homebrew` in `release.yml`); the GitHub Release itself is created by release-please, not this pipeline. The `server.json` version is patched from the git tag at publish time.
