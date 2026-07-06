# Copilot code review instructions for mcp-stdio

## Repository overview

`mcp-stdio` is a **stdio-to-HTTP/SSE gateway/relay** for the Model Context
Protocol. It translates between the stdio JSON-RPC framing that MCP hosts
(Claude Code, Claude Desktop, etc.) speak and the two MCP HTTP transports
that remote servers expose:

- Streamable HTTP (current spec) — `run()` in `src/mcp_stdio/relay.py`
- Legacy SSE (2024-11-05) — `run_sse()` in `src/mcp_stdio/relay.py`

**This repo implements zero MCP tools of its own.** There is no FastMCP, no
`@mcp.tool()` decorator, nothing that "wraps a tool return value" — do not
review this code as if it were an MCP tool server. Its entire job is to
faithfully relay a stdio stream to/from an HTTP endpoint, plus a full OAuth
2.1 client (`oauth.py`) and on-disk token cache (`token_store.py`) to
authenticate against that endpoint. Other modules: `cli.py` (argparse
entry point, `mcp-stdio` → `mcp_stdio.cli:main`).

Only runtime dependency: `httpx`. Build backend: `hatchling`.

## Build & validate

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

CI (`.github/workflows/test.yml`) runs `pytest tests/ -v` on Python 3.10–3.14
on `ubuntu-latest`, plus a dedicated `windows-latest` / Python 3.12 job. The
Windows job exists specifically to smoke-test the stdio newline handling
(see "Windows CRLF" below) — it is not there for general cross-platform
coverage, so don't suggest dropping it as redundant.

## Review focus

### 1. Stdout hygiene — the single highest-value thing to get right here

Because this process's stdout *is* the JSON-RPC wire to the MCP host, any
stray byte on stdout corrupts the protocol. The codebase already has the
correct, verified pattern — preserve it, don't reinvent it:

- `log(msg)` (module-level in `relay.py`) writes exclusively to
  `sys.stderr` via `print(f"[mcp-stdio] {msg}", file=sys.stderr, flush=True)`.
  All diagnostic/warning output, in both `relay.py` and `oauth.py`, must go
  through this helper (or an equivalent explicit `file=sys.stderr`) — never
  a bare `print()`.
- All JSON-RPC output goes through `_write_line()` / `_emit()`, which write
  to `sys.stdout` under `_STDOUT_LOCK` (content + trailing `\n` as one
  atomic write, since `run_sse` has two writers — the SSE reader thread and
  the main loop — and unsynchronized `print` calls could interleave
  mid-line).

Flag any diff that adds a new output path (new log line, new exception
handler, a debug print left in, a new writer to stdout) if it doesn't route
through `log()` for diagnostics or `_write_line()`/`_emit()` for protocol
messages. A raw `print()` anywhere in `relay.py`/`oauth.py`/`cli.py` that
isn't going to stderr is a bug, not a style nit.

### 2. Token storage security

`token_store.py` persists OAuth tokens at `~/.config/mcp-stdio/tokens.json`
(with legacy `~/.mcp-stdio/` migration on read):

- The store directory is created `0o700` (`stat.S_IRWXU`); the token file
  itself is written/chmod'd `0o600` (`stat.S_IRUSR | stat.S_IWUSR`), applied
  via `fchmod`/`os.chmod` on an already-opened fd rather than a path-based
  chmod, specifically to avoid a TOCTOU/symlink race (opens use
  `os.O_NOFOLLOW`). A diff that reintroduces a path-based chmod, widens the
  mode, or opens the file without `O_NOFOLLOW` should be rejected.
- Client credentials and refresh tokens are stored alongside access tokens
  for reuse (see the DCR/refresh-token workarounds below) — any new field
  added to the stored record should go through the same 0o600 file, never a
  separate world-readable path or a log line.
- `oauth.py` logs plenty of diagnostic detail (malformed URLs, discovery
  fallbacks, scheme/origin rejections) but always via `log()` to stderr, and
  never logs the token, client secret, or PKCE `code_verifier` values
  themselves. A diff that adds a new `log()` call in an OAuth code path
  should be checked that it doesn't interpolate a secret/token value into
  the message.

### 3. Cancellation tracking (`_CancelTracker` / `_emit`)

Both transports implement the MCP cancellation spec's receiver-side
SHOULD via a shared `_CancelTracker` (id → timestamp map, 60s TTL,
`add`/`contains`/`consume`/`discard`) gating `_emit()`: an id seen in a
`notifications/cancelled` on stdin causes the next matching JSON-RPC
*response* (object with an id and `result`/`error`, no `method`) to be
dropped before it reaches stdout. This exists to protect against known
client-side bugs where a late response to a cancelled call corrupts the
client's stdio framing.

A diff that touches reconnect/retry logic (either transport's backoff, the
SSE reconnect path, or `_drain_pending`/`-32000` synthesis on stream drop)
should be checked against whether it preserves this gate — a synthesized
error or a retried response must still flow through `_emit` (or otherwise
consult the tracker), not bypass it via a direct `_write_line`. The one
intentional bypass is mcp-stdio's own `_error_response` output, which calls
`_write_line` directly by design so a cancel mid-retry doesn't leave the
client hanging — don't flag that path, but do flag any *new*
direct-`_write_line` call added elsewhere.

### 4. Gotchas from WORKAROUNDS.md relevant to review

`WORKAROUNDS.md` documents 20+ upstream bugs this project works around.
Three that are easy to accidentally regress in a routine-looking diff:

- **Late response after cancel drops the stdio transport**
  (anthropics/claude-code#51073, modelcontextprotocol/python-sdk#2480) — the
  motivating bug for `_CancelTracker` above. A "simplification" of the
  emit/cancel path that removes the id-drop gate would silently reopen this
  failure mode (reconnect storms costing 5–10s per cycle under heavy cancel
  usage).
- **SSE stream drop must synthesize `-32000` for in-flight requests**
  (anthropics/claude-code#60061) — `run_sse`'s reconnect logic tracks every request
  id POSTed on the current stream in `_SseState.pending` and, on disconnect,
  synthesizes a JSON-RPC `-32000` error for each one still awaiting a reply
  (skipping already-cancelled ids) before reconnecting. A diff that changes
  the SSE reconnect flow should be checked that it still drains `pending`
  this way rather than leaving those requests to hang forever.
- **`Mcp-Session-Id` must be echoed on every request after `initialize`**
  (anthropics/claude-code#70386) — the Streamable HTTP `run()` path captures
  the `Mcp-Session-Id` response header from `initialize` and re-sends it on
  every subsequent request. A refactor of the request-building code in `run()`
  that drops this header on any request type would break session-aware
  servers even though `initialize` itself still succeeds.

## Out of scope

This is not an MCP tool server. Do not apply, or ask for, generic MCP
tool-server review conventions here — there is no `@mcp.tool()` decorator,
no tool content envelope, no tool schema to validate. If a review comment
would only make sense for a server that implements MCP tools, it doesn't
apply to this repository.
