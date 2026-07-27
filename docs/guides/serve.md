# Publish your stdio server

Goal: a stdio MCP server on your host becomes an HTTPS Streamable HTTP
endpoint that remote MCP clients — Claude Desktop, Claude Code, even
Claude.ai custom connectors — can use, each user isolated in their own
child process behind a real OAuth 2.1 login.

## 1. Smoke test on loopback

```bash
mcp-stdio serve --enable-oauth --public-url http://127.0.0.1:8080 \
  --dev-user alice --port 8080 -- python -m my_mcp_server
```

and from a second terminal, connect to it with mcp-stdio's own client mode:

```bash
mcp-stdio --check --oauth http://127.0.0.1:8080/mcp
```

`--dev-user` is an **insecure** stand-in identity for loopback testing
only — it lets you exercise the whole OAuth flow without a real login. If
`--check` reports a successful `initialize`, the gateway works; everything
after this is deployment.

## 2. Deploy behind your reverse proxy

In production the identity comes from your SSO. Terminate TLS and
authentication at a reverse proxy (nginx, Apache, …) and pass the logged-in
user to mcp-stdio in a trusted header:

```bash
mcp-stdio serve --enable-oauth \
  --public-url https://mcp.example.com \
  --trusted-user-header X-Forwarded-User \
  --token-store /var/lib/mcp-stdio/state.json \
  --session-idle-ttl 180 \
  -- python -m my_mcp_server
```

- `--public-url` pins the OAuth issuer to your public address (required
  behind a proxy).
- `--trusted-user-header` names the header your proxy sets **and strips
  from client requests** — that stripping is what makes it trustworthy.
- `--token-store` persists issued tokens, registrations, and replay
  tombstones (`0600`) so **a restart or redeploy does not log everyone
  out**. Without it, every deploy invalidates all tokens. One path per
  serve process — a sidecar `.lock` refuses accidental sharing.
- `--session-idle-ttl` reaps children whose client vanished without a
  clean disconnect.

What you get per connecting user: their own child process (spawned at
`initialize`, destroyed on disconnect or idle timeout), their session bound
to their authenticated identity — another user's session id is a `404`, not
a crossover.

## 3. Optional add-ons

| You need… | Do this |
|---|---|
| Claude.ai custom connectors (browser-based clients) | `--allow-redirect-uri https://claude.ai/api/mcp/auth_callback` |
| Several backends on one host | run one serve process per backend with path-scoped issuers: `--public-url https://mcp.example.com/team-a`, `…/team-b` — AS endpoints and well-known documents nest under each prefix |
| Cap concurrent users | `--max-sessions N` (default 100; excess `initialize` gets `503`) |
| Static token instead of OAuth | drop `--enable-oauth`, set `MCP_STDIO_SERVE_TOKEN` |
| Longer / shorter access tokens | `--access-token-ttl SECONDS` (default 3600) |

## Notes for operators

- The embedded authorization server implements Dynamic Client Registration,
  PKCE (S256 only), refresh rotation with replay detection, and RFC 8707
  audience binding — MCP clients discover all of it via the standard
  well-known documents; there is nothing to configure client-side.
- Treat `--token-store`'s file like a private key. It is created `0600` in
  a `0700` directory.
- Every request is logged to stderr with query strings redacted.
- Session handling is strict and lifecycle-correct: requests route by
  `Mcp-Session-Id` only (never by JSON-RPC request id), and each session has its
  own child. A fresh `initialize` mints a new session; an unknown or terminated
  id returns `404` for a clean re-initialize. Responses are correlated within a
  session by JSON-RPC id and are never cross-wired: a client that reuses an id
  *sequentially* is matched correctly, and a second request reusing an id
  already *in flight* on the same session with a DIFFERENT payload is rejected
  (`409`, since MCP requires request ids to be unique within a session) rather
  than silently delivering the wrong reply; each such rejection is logged to
  stderr with the conflicting id and both requests' methods. A same-id request with the SAME
  payload (compared as parsed JSON, so a re-serialized retry with a different
  key order still matches) arriving while the first is still outstanding — the
  shape seen when a client's reconnect burst re-fires a request against itself
  right after a restart or idle-reclaim — is instead treated as a retry: it is
  piggybacked onto the in-flight request, and every waiter still attached when
  the reply arrives gets that same `200` reply, not `409`. Two caveats: each
  waiter keeps its own deadline (a caller whose timeout expires before the
  shared reply lands gets its own `504` while a later-attached retry can still
  succeed), and a retry landing just *after* the first copy completed is
  indistinguishable from legitimate sequential id reuse, so it is dispatched
  anew — do not rely on that window being deduplicated for non-idempotent
  calls. serve cannot make a client that mints a brand-new session id on every
  call persist state — that is the client's own behavior.

Real-world reference: this is the exact setup used to publish several
stdio MCP servers under one host, surviving routine redeploys without
users noticing. If your backend needs per-user credentials *inside* the
child process, that is a design decision of your server — the gateway
intentionally does not forward identity into the child.
