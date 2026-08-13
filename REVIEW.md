# Review rules for this repository

Review rules for this repository, on top of the reviewer's default
focus. Three things: which findings are blocking here, which classes to
report that the default focus would otherwise skip, and which are
noise. The reasoning behind the rules lives in
`.github/copilot-instructions.md` (its numbered sections are cited
below) and `CLAUDE.md`, both of which the reviewer also receives.

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
- **A weakened serve-mode auth, isolation or session guard (§5).** A
  widened `--token-store` mode, a relaxed token or PKCE check, weakened
  Host-header sanitization, one session's backend child answering
  another session's request, a child leaked on teardown, or the
  404-on-unknown-session-id guard dropped. Isolation on the modern path
  counts the same: `ModernBackendPool` is keyed on the authenticated
  principal precisely so child state cannot cross an authorization
  boundary, so re-keying or sharing it is this class too, not a lesser
  one for lacking a session id.
- **Bypassing the cancellation gate (§3).** A new response path that
  neither goes through `_emit` nor consults `_CancelTracker` some other
  way — reconnect, retry and `-32000` synthesis included. Consulting
  the tracker directly is a legitimate form of the gate, not a bypass:
  `_drain_pending` writes via `_error_response` and skips cancelled ids
  through the deliberately non-consuming `tracker.contains`. What is
  blocking is dropping the check, not declining `_emit`.
- **Breaking a protocol-era invariant (§6).** Wire-changing behavior
  reachable from a legacy request without an era gate, a new `-32002`,
  or an invented code inside `-32020..-32099`.
- **Any diff at all to `tests_integration/test_serve_legacy_pin.py`.**
  That file's own module docstring settles the scope: the zero-diff
  claim is "LITERAL, with no exceptions carved into it", and tests
  expected to move live in `test_serve_modern_before.py` precisely so
  this invariant stays enforceable by a reviewer reading a diff rather
  than a docstring. Report the edit and ask for the justification; a
  deliberate, reviewed change is exactly what the rule wants surfaced,
  so a legitimate one costs nothing. Do not narrow this to "behavior"
  pull requests — the file is explicit that no such carve-out exists.

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
- **Re-litigating** a decision the pull request description in front of
  you already settles — this repository writes explicit divergence
  ledgers and adopted-defaults sections. Judge that from the
  description text you were actually given: it arrives truncated and
  linked design records are not fetched, so never suppress a finding on
  the assumption that a record you cannot see probably settles it.
