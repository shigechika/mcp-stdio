# Review rules for this repository

Severity rules for the AI reviewer. The reasoning behind each one lives
in `.github/copilot-instructions.md` (its numbered sections are cited
below) and `CLAUDE.md`, both of which the reviewer also receives — this
file only decides what is blocking and what is noise.

## Always blocking

- **Relay-mode stdout hygiene (§1).** In `relay.py`, `oauth.py` or
  `cli.py`: a bare `print()` not going to stderr, or any new output
  path that does not route through `log()` for diagnostics or
  `_write_line()` / `_emit()` for protocol messages. Stdout there is
  the JSON-RPC wire. This rule does **not** extend to `server.py`,
  where the process's stdout is not a wire.
- **Token store permissions (§2).** A path-based `chmod` replacing the
  fd-based one, a widened file mode, or an open without `O_NOFOLLOW`.
- **A secret reaching a log line (§2, §5).** An access or refresh
  token, a client secret, a PKCE `code_verifier`, or a serve-mode
  bearer interpolated into a `log()` call or otherwise written out, at
  any level.
- **A weakened serve-mode auth or session guard (§5).** A widened
  `--token-store` mode, a relaxed token or PKCE check, one session's
  backend child answering another session's request, a child leaked on
  teardown, or the 404-on-unknown-session-id guard dropped.
- **Bypassing the cancellation gate (§3).** A new direct `_write_line`
  call for a response that should pass through `_emit` and
  `_CancelTracker` — reconnect, retry and `-32000` synthesis paths
  included. (`_error_response`'s existing direct write is the one
  intentional bypass; see below.)
- **Breaking a protocol-era invariant (§6).** Editing
  `tests_integration/test_serve_legacy_pin.py` at all, wire-changing
  behavior reachable from a legacy request without an era gate, a new
  `-32002`, or an invented code inside `-32020..-32099`.

## Report even though the default focus would not

- **A comment or docstring claim the code contradicts (§7)** — blocking
  when the claim states an invariant. Code review normally excludes
  comment accuracy outright; here it is the most recurring real finding
  class this repository has, because its docstrings state binding
  invariants. Quote the claim and the code that falsifies it. A false
  claim is a finding even when the code itself is correct.
- **A vacuous negative assertion in a test (§8)**, as advisory. When a
  test asserts something did *not* happen, ask what it would do if the
  observed process or stream were already dead. If it would still pass,
  report it — even though test quality is not a bug the diff
  introduces.
- **A release-owned file edited by hand (§9)**, as advisory:
  `__version__` in `src/mcp_stdio/__init__.py`, or `CHANGELOG.md`, in a
  feature PR. release-please owns both.
- **A new runtime import outside stdlib and httpx (§9)**, as advisory.
  Test-only dependencies belong in the `dev` / `integration` extras.
- **A bilingual doc sibling left behind (§9)**, as advisory: a change
  to `README.md` or a `docs/*.md` with no matching `.ja` change or the
  reverse, and a duplicated `<a id=…>` anchor within a page.

## Never report

- **Generic MCP tool-server conventions.** This is not a tool server:
  there is no `@mcp.tool()` decorator, no tool content envelope, no
  tool schema to validate. A comment that would only make sense for a
  server implementing MCP tools does not apply here.
- Formatting, import order and style. Those belong to ruff in CI.
- The relay's grandfathered cold-start `-32002` (§6) and
  `_error_response`'s direct `_write_line` (§3). Both are deliberate.
- A decision the PR body's divergence ledger or a linked design record
  already documents. Note a disagreement once at most, citing the
  record; do not re-litigate it.
