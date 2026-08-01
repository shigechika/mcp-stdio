# Copilot code review instructions for mcp-stdio

## Repository overview

`mcp-stdio` is a **stdio-to-HTTP/SSE gateway/relay** for the Model Context
Protocol. It translates between the stdio JSON-RPC framing that MCP hosts
(Claude Code, Claude Desktop, etc.) speak and the MCP HTTP transports
that remote servers expose:

- Streamable HTTP — `run()` in `src/mcp_stdio/relay.py`, speaking **two
  protocol eras**: 2025-06-18 (legacy, the default) and 2026-07-28
  (modern, opt-in via `--protocol-era modern|auto`; era detected by a
  `server/discover` probe). The modern era adds per-request `_meta` +
  `Mcp-Method`/`Mcp-Name` headers, no sessions, background
  `subscriptions/listen` streams (including `resources/subscribe`
  interception), an MRTR bridge translating `input_required` results into
  legacy `elicitation`/`sampling`/`roots` round-trips, and a stdin reader
  thread that aborts the in-flight POST on `notifications/cancelled`.
- Legacy SSE (2024-11-05) — `run_sse()` in `src/mcp_stdio/relay.py`
  (`--protocol-era` is ignored there, with a warning)

**This repo implements zero MCP tools of its own.** There is no FastMCP, no
`@mcp.tool()` decorator, nothing that "wraps a tool return value" — do not
review this code as if it were an MCP tool server. It works in **two
directions**:

- **relay** (the original job, `relay.py`) — faithfully relays a stdio stream
  to/from a remote HTTP endpoint (client side: stdin/stdout in, HTTP out),
  plus a full OAuth 2.1 client (`oauth.py`) and on-disk token cache
  (`token_store.py`) to authenticate against that endpoint.
- **serve** (`server.py`, `mcp-stdio serve`) — the mirror image (server side:
  HTTP in, stdio out): spawns a local stdio MCP server as a child process
  and publishes it as a Streamable HTTP endpoint so clients that
  can't spawn the server locally can reach it over the network. **Dual-era
  on one endpoint**: `_request_era()` classifies each POST conservatively
  (modern only on positive evidence — `params._meta` carries the
  protocolVersion key, or the method is `server/discover`); legacy clients
  keep the sessioned per-child model unchanged, modern clients are served
  statelessly from a principal-keyed `ModernBackendPool` behind a
  request-validation ladder. Stdlib-only
  (`http.server` + `subprocess`); optional layered auth (open / static bearer
  / embedded OAuth 2.1 authorization server). See Review focus §5 and §6.

Other modules: `cli.py` (argparse entry point, `mcp-stdio` →
`mcp_stdio.cli:main`; also dispatches `serve` to `server.py`).

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
(see the "## Windows" section in `WORKAROUNDS.md`) — it is not there for
general cross-platform coverage, so don't suggest dropping it as redundant.

A separate **integration suite** lives in `tests_integration/` (advisory
`integration.yml` job, ubuntu-only): real localhost HTTP against a
python-sdk v2.x reference peer (the `integration` extra pins `mcp>=2.0,<3`)
and against `mcp-stdio serve` itself. It
is deliberately NOT part of `pytest tests/` — the unit suite's working
convention (not an enforced rule; there is no socket-blocking plugin) is
mocked HTTP via pytest-httpx and patched sleeps throughout, and a diff
adding a real socket or a bare `time.sleep` to `tests/` deserves a
comment; the integration conftest works differently, with bounded polls
and a per-test timeout. `mcp`/`uvicorn` live only in the
`integration` optional-dependency extra and must never appear in
`[project.dependencies]`.

## Review focus

### 1. Stdout hygiene (relay mode) — the single highest-value thing to get right here

Because the relay process's stdout *is* the JSON-RPC wire to the MCP host,
any stray byte on stdout corrupts the protocol. (This applies to the
**relay** path — `relay.py`, `oauth.py`, `cli.py`. In `serve` mode the
process's stdout is *not* the wire — the wires there are each backend
child's stdin/stdout and the HTTP socket — so §5 governs that code, not this
rule.) The codebase already has the correct, verified pattern — preserve it,
don't reinvent it:

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

### 5. Serve mode (`server.py`) — auth, sessions, and Host-header hygiene

`mcp-stdio serve` (dispatched from `cli.py` when `argv[1] == "serve"`) is the
repo's largest module and its only network-listening / credential-issuing
surface. The stdout-hygiene rule of §1 does **not** apply here — in serve
mode the process's stdout is not the protocol wire; the wires are each
backend child's stdin/stdout and the HTTP socket. The highest-stakes review
targets:

- **Layered auth.** Open by default; `--auth-token` adds a static-bearer
  Resource Server gate; `--enable-oauth` adds an *embedded OAuth 2.1
  authorization server* (issues tokens, optionally persisted to a 0o600 file
  via `--token-store`). The static bearer should be passed via the
  `MCP_STDIO_SERVE_TOKEN` env var rather than `--auth-token`, because the
  flag is visible in `ps` (`_SERVE_TOKEN_ENV`). Flag a diff that logs a
  bearer/OAuth token, prints one, widens the `--token-store` file mode, or
  weakens a token/PKCE check — same standard as §2.
- **Session lifecycle.** One backend child process per MCP session
  (`SessionRegistry`, keyed on `Mcp-Session-Id`): the transport mints a
  session id on `initialize`, returns 404 on an unknown id, terminates on
  DELETE, and serves server-initiated messages over a GET SSE stream. Flag a
  diff that lets one session's child answer another session's request, leaks
  a child on teardown, or drops the 404-on-unknown-id guard.
- **Host-header sanitization.** Incoming `Host` / `X-Forwarded-Host` values
  are filtered through `_HOST_ALLOWED` before being echoed into the
  `WWW-Authenticate` challenge or the Protected Resource Metadata JSON, to
  block header injection. Flag a diff that uses a raw/unsanitized Host value
  in those responses.
- **Modern pool isolation.** Modern-era requests are served from
  `ModernBackendPool`, keyed on the **authenticated principal** (one shared
  child under no-auth/static-token, one per OAuth user) — never on a
  session. Flag a diff that lets one principal's child serve another
  principal's request, evicts a pending/busy child (the eviction guard
  exists because both cases were review findings), or drops a dead child
  without reaping it (`backend.shutdown()` — skipping it leaks an OS
  zombie per respawn).

### 6. Protocol-era invariants (the #270 migration rules)

The 2026-07-28 support was built under two hard rules that remain binding
for every future diff:

- **The legacy paths are byte-frozen.** On the relay, a legacy-era session
  must produce wire bytes identical to pre-#270 releases; on serve, legacy
  clients keep the exact sessioned behavior. The pinned evidence is
  `tests_integration/test_serve_legacy_pin.py` — a **zero-diff file**: a
  behavior PR that edits it is prima facie breaking the freeze, and that
  edit itself deserves a review comment asking for justification.
- **New behavior is era-gated.** Anything that changes what goes on the
  wire must sit behind the modern-era branch (`era == "modern"` on the
  relay; `_request_era()` returning modern on serve). A new call site
  reachable from a legacy request is a finding.
- **Error-code discipline.** New code must not emit `-32002` (forbidden by
  the 2026-07-28 spec) and must not invent codes in the reserved
  `-32020..-32099` range beyond the defined `-32020`/`-32021`/`-32022`.
  The relay's pre-existing cold-start `-32002` is grandfathered — do not
  flag it.

### 7. Comment/docstring accuracy — check claims against code

Docstrings and comments in this repo state binding invariants, and
comment-vs-code contradictions are its single most recurring review
finding class (examples that shipped and were later caught: a "zero
threads" claim falsified by an always-on daemon; a teardown-order comment
stating the reverse of the code; a "(logged once)" promise with no latch;
a "guards are not duplicated" claim above duplicated predicates). When a
diff adds or edits a claim-bearing comment, verify the claim against the
code in the same diff; when a diff changes code near a claim-bearing
comment, verify the comment still holds. A false claim is a real finding
even when the code is correct.

### 8. Test soundness — vacuous negative observations

An assertion of absence ("no late response arrived", "nothing was
forwarded", "no reconnect happened") is only meaningful over a channel
that is proven alive. Three shipped instances were caught in review:
`drain()` treating relay EOF as quiet success (a crashed relay made every
"nothing arrived" assertion pass); a length-snapshot slice into a bounded
`deque(maxlen=…)` that goes empty after saturation; an SSE reader
signalling "opened" without checking status/content-type. When a test asserts that
something did NOT happen, check what the assertion would do if the
observed process/stream were already dead — if the answer is "still
pass", flag it.

### 9. Release and dependency discipline

- `src/mcp_stdio/__init__.py` (`__version__`) and `CHANGELOG.md` are owned
  by release-please — any manual edit to either in a feature PR is a
  finding.
- The runtime dependency set is **httpx only**. A new import in
  `src/mcp_stdio/` must be stdlib or httpx; test-only dependencies belong
  in the `dev`/`integration` extras.
- Docs are bilingual siblings: a change to `README.md` or `docs/*.md`
  without the matching `.ja` change (or vice versa) is incomplete, and
  explicit `<a id=…>` anchors must stay unique per page (a duplicated
  anchor was a shipped review finding).

## Reporting bar

High-signal reviews keep this repository's fix loops short. Before
reporting a finding, it must clear all of these:

- **A concrete failure scenario** — name the input or state and the wrong
  outcome, anchored to lines this PR changes. For the claim-accuracy and
  process classes (§7, §9), which have no runtime failure by construction,
  the equivalent is: quote the claim or rule and the code or file that
  falsifies it. "Might be worth considering…" and "for robustness…" do
  not clear the bar either way.
- **Not pre-existing** — if the behavior exists on `main` untouched by
  this diff, it is out of scope here.
- **Not a settled decision** — PR bodies in this repo carry explicit
  divergence ledgers and adopted-defaults sections, and design records
  live on the linked issues. If the PR body or linked design record
  already documents the choice you are about to question, do not
  re-litigate it; at most note the disagreement once, referencing the
  record.
- **Not a linter's job** — formatting, import order, and style belong to
  ruff/CI, not review comments.

When uncertain whether a finding is real, prefer omitting it: a missed
borderline nit costs little, while a speculative finding costs a fix
round.

## Out of scope

This is not an MCP tool server. Do not apply, or ask for, generic MCP
tool-server review conventions here — there is no `@mcp.tool()` decorator,
no tool content envelope, no tool schema to validate. If a review comment
would only make sense for a server that implements MCP tools, it doesn't
apply to this repository.
