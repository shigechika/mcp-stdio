"""Reverse gateway: expose a local stdio MCP server as a Streamable HTTP endpoint.

This is the mirror image of :mod:`mcp_stdio.relay`. ``relay`` is the client
side (stdio in, HTTP out); this module is the server side (HTTP in, stdio out):
it spawns a local stdio MCP server as a child process and publishes it as a
Streamable HTTP MCP endpoint, so clients that cannot spawn the server locally
(a laptop without it installed, a remote bot) can reach it over the network.

One backend child PER SESSION. Authentication is optional and layered: with no
token the endpoint is open; ``--auth-token`` adds a static-bearer Resource
Server gate; ``--enable-oauth`` adds an embedded OAuth 2.1 Authorization
Server. The HTTP surface implements the MCP Streamable HTTP transport's
request/response and notification semantics, session management (an
``Mcp-Session-Id`` minted on ``initialize``, 404 on an unknown id, DELETE to
terminate), plus a GET SSE channel for server-initiated messages.

Stdlib only (``http.server`` + ``subprocess`` + ``threading``), matching the
project's httpx-only-runtime constraint: the server path adds no dependency.

Concurrency model: each MCP session owns a dedicated backend child (see
:class:`SessionRegistry`) that speaks newline-delimited JSON-RPC over its
stdin/stdout. Per child, a single reader thread drains stdout and routes each
message — a response (id + result/error, no method) wakes the waiting HTTP
handler keyed by the JSON-RPC id; anything server-initiated (carries
``method``) is queued for that session's GET SSE stream.

Multi-client isolation is by process boundary: concurrent clients land on
distinct sessions and distinct children, so a JSON-RPC id collision across
clients cannot cross responses (each id is unique within its own child).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from .relay import log

# Bound how long an HTTP request waits for the backend to answer before the
# handler synthesizes a JSON-RPC error. A backend that wedges must not pin the
# HTTP connection open forever.
_BACKEND_RESPONSE_TIMEOUT_SECS = 120.0

# How long a GET SSE stream blocks on the outbound queue before emitting an
# SSE comment as a keepalive (also the cadence at which it notices shutdown).
_SSE_KEEPALIVE_SECS = 15.0

# RFC 9728 Protected Resource Metadata well-known prefix. The full metadata URL
# inserts this between origin and the resource path (RFC 9728 Sec. 3.1), e.g.
# resource ``https://h/mcp`` -> ``https://h/.well-known/oauth-protected-resource/mcp``.
_PRM_WELL_KNOWN_PREFIX = "/.well-known/oauth-protected-resource"

# Environment variable carrying the gateway's static bearer token. Preferred
# over the --auth-token flag, which would expose the token in ``ps`` output.
_SERVE_TOKEN_ENV = "MCP_STDIO_SERVE_TOKEN"

# Host characters we allow when reflecting a (possibly proxy-supplied) Host /
# X-Forwarded-Host into an absolute metadata URL. Restricting to this set keeps
# a hostile Host header from injecting a quote/space into the quoted
# ``resource_metadata`` challenge parameter or the JSON body.
_HOST_ALLOWED = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:[]"
)


def _sanitize_host(host: str) -> str:
    """Keep only safe host[:port] characters; empty -> caller falls back."""
    return "".join(c for c in host if c in _HOST_ALLOWED)


def _classify(msg: Any) -> str:
    """Classify a parsed JSON-RPC message for routing.

    Returns one of ``"request"`` (method + id — expects a response),
    ``"notification"`` (method, no id), ``"response"`` (id + result/error,
    no method — e.g. a client answering a server-initiated request), or
    ``"invalid"`` (anything else, including non-objects and batches, which
    not handled here).
    """
    if not isinstance(msg, dict):
        return "invalid"
    has_method = "method" in msg
    has_id = "id" in msg
    if has_method and has_id:
        return "request"
    if has_method and not has_id:
        return "notification"
    if not has_method and has_id and ("result" in msg or "error" in msg):
        return "response"
    return "invalid"


def _error_body(message: str, req_id: Any = None) -> str:
    """Build a JSON-RPC error response line (-32000 server error)."""
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": message},
            "id": req_id,
        }
    )


class BackendProcess:
    """Manage one stdio MCP child process and route its output by JSON-RPC id.

    A single daemon reader thread consumes the child's stdout line by line.
    Each line is parsed once: a JSON-RPC *response* resolves the per-id slot a
    waiting HTTP handler is blocked on; a server-initiated *request* or
    *notification* (anything carrying ``method``) is pushed onto
    ``server_initiated`` for the GET SSE stream to deliver.
    """

    def __init__(self, command: list[str]) -> None:
        if not command:
            raise ValueError("backend command is empty")
        self._command = command
        # text mode + line buffering so the reader thread sees one JSON-RPC
        # message per iteration. errors="replace" keeps a stray non-UTF-8 byte
        # from killing the reader (matching relay's never-crash posture).
        self._proc = subprocess.Popen(  # noqa: S603 — operator-supplied argv
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # inherit: backend logs flow to the gateway's stderr
            text=True,
            bufsize=1,
            errors="replace",
        )
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        # id -> single-slot holder {"event": Event, "line": str|None}
        self._pending: dict[Any, dict[str, Any]] = {}
        # Server-initiated messages (requests/notifications) awaiting an SSE
        # consumer. Unbounded queue is acceptable for one client per session;
        # a later change can bound + shed.
        self.server_initiated: "queue.Queue[str]" = queue.Queue()
        self._closed = threading.Event()
        self._reader = threading.Thread(
            target=self._read_loop, name="backend-reader", daemon=True
        )
        self._reader.start()

    @property
    def command(self) -> list[str]:
        return list(self._command)

    def _read_loop(self) -> None:
        """Drain backend stdout, routing each line until EOF."""
        stdout = self._proc.stdout
        assert stdout is not None
        try:
            # readline (not `for raw in stdout`): the iterator form read-aheads
            # an internal buffer and can withhold a completed line until more
            # arrives, delaying responses. readline returns each line as soon
            # as the child flushes it.
            while True:
                raw = stdout.readline()
                if raw == "":
                    break  # EOF: backend closed stdout / exited
                # The child speaks NDJSON; a CRLF writer (or our own LF policy)
                # may leave a trailing \r — strip both. Blank keepalive lines
                # are ignored.
                line = raw.rstrip("\r\n")
                if not line.strip():
                    continue
                self._route(line)
        except Exception as e:  # pragma: no cover - defensive
            log(f"backend reader error: {e}")
        finally:
            self._fail_all("backend process exited")

    def _route(self, line: str) -> None:
        try:
            msg = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            # Non-JSON noise on the JSON-RPC channel: surface it on the SSE
            # stream rather than dropping silently, so a debugging operator can
            # see it. It cannot be a response (unparseable), so it never
            # correlates to a pending id.
            self.server_initiated.put(line)
            return
        kind = _classify(msg)
        if kind == "response":
            rid = msg.get("id")
            with self._lock:
                slot = self._pending.get(rid)
                if slot is not None:
                    slot["line"] = line
                    slot["event"].set()
                    return
            # No waiter (timed-out, or an id we never sent): expose on SSE
            # rather than lose it.
            self.server_initiated.put(line)
        else:
            # request / notification / invalid — all server-initiated toward
            # the client.
            self.server_initiated.put(line)

    def send_request(self, line: str, req_id: Any, timeout: float) -> str | None:
        """Forward a request line and block for its response.

        Returns the backend's response line, or ``None`` on timeout / backend
        death (the caller then synthesizes a JSON-RPC error).
        """
        event = threading.Event()
        slot = {"event": event, "line": None}
        with self._lock:
            if self._closed.is_set():
                return None
            # Reuse-of-an-in-flight-id is a client bug; last writer wins and the
            # earlier waiter will time out. Acceptable: one client per session.
            self._pending[req_id] = slot
        if not self._write(line):
            with self._lock:
                self._pending.pop(req_id, None)
            return None
        ok = event.wait(timeout)
        with self._lock:
            self._pending.pop(req_id, None)
        return slot["line"] if ok else None

    def send_oneway(self, line: str) -> bool:
        """Forward a notification or a client->server response (no reply)."""
        return self._write(line)

    def _write(self, line: str) -> bool:
        stdin = self._proc.stdin
        if stdin is None or self._closed.is_set():
            return False
        try:
            with self._write_lock:
                stdin.write(line + "\n")
                stdin.flush()
            return True
        except (BrokenPipeError, ValueError, OSError) as e:
            # ValueError: write on a closed file. OSError/BrokenPipe: backend
            # gone. Mark closed so in-flight + future calls fail fast.
            log(f"backend write failed: {e}")
            self._fail_all("backend process exited")
            return False

    def _fail_all(self, _reason: str) -> None:
        """Mark closed and wake every waiter so none blocks forever."""
        if self._closed.is_set():
            return
        self._closed.set()
        with self._lock:
            waiters = list(self._pending.values())
            self._pending.clear()
        for slot in waiters:
            slot["event"].set()  # line stays None -> caller emits error

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    def shutdown(self) -> None:
        """Terminate the backend child, escalating to kill if needed."""
        self._fail_all("gateway shutting down")
        proc = self._proc
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception as e:  # pragma: no cover - defensive
            log(f"backend shutdown error: {e}")


# --- per-session backend registry: one child stdio server per MCP session ---

# Hard cap on concurrent sessions: a fork-bomb guard for an open (no-auth)
# gateway, since each session spawns a child process. High enough that a single
# logical client never trips it; override with ``--max-sessions``.
_DEFAULT_MAX_SESSIONS = 100

# Longest a reaper tick waits between idle sweeps. A small TTL is swept more
# often; a large one no less than once a minute.
_MAX_REAP_INTERVAL_SECS = 60.0


class _Session:
    """A live MCP session: its backend child plus last-activity timestamp."""

    __slots__ = ("backend", "last_active")

    def __init__(self, backend: BackendProcess, last_active: float) -> None:
        self.backend = backend
        self.last_active = last_active


class SessionRegistry:
    """Thread-safe map of ``Mcp-Session-Id`` -> backend child process.

    Each MCP session gets its OWN stdio backend, so concurrent clients are
    isolated by process boundary rather than multiplexed onto one shared child
    (which could cross responses on a JSON-RPC id collision). A session is
    created when a client POSTs ``initialize`` (the gateway mints an id and
    spawns a dedicated :class:`BackendProcess`), looked up by that header on
    every later request, and removed on DELETE or gateway shutdown.

    The slow operations — spawning a child (``Popen`` exec) and tearing one
    down (``terminate()`` then ``wait``) — run OUTSIDE the lock; only the dict
    mutation is guarded, so one session's lifecycle never serializes another's.

    When ``idle_ttl`` is set (``> 0``), a background reaper (started by
    :meth:`start_reaper`) sweeps sessions whose last activity is older than the
    TTL — and any whose child has already exited — so a client that disconnects
    without DELETE does not pin a slot forever. ``now`` is injectable so tests
    can drive eviction on a fake clock.
    """

    def __init__(
        self,
        command: list[str],
        *,
        max_sessions: int = _DEFAULT_MAX_SESSIONS,
        idle_ttl: float = 0.0,
        now: Any = time.monotonic,
    ) -> None:
        if not command:
            raise ValueError("backend command is empty")
        self._command = command
        self._max = max_sessions
        self._idle_ttl = idle_ttl
        self._now = now
        self._lock = threading.Lock()
        self._sessions: dict[str, _Session] = {}
        self._reaper: threading.Thread | None = None
        self._reaper_stop = threading.Event()

    def create(self) -> tuple[str, BackendProcess] | None:
        """Spawn a child for a new session.

        Returns ``(session_id, backend)``, or ``None`` when the concurrent-
        session cap is reached (the caller then responds 503).
        """
        with self._lock:
            if len(self._sessions) >= self._max:
                return None
        # Spawn outside the lock: a Popen exec must not serialize other
        # sessions' creation or routing.
        backend = BackendProcess(self._command)
        # MCP spec: the session id SHOULD be globally unique and
        # cryptographically secure, and MUST contain only visible ASCII.
        sid = secrets.token_hex(16)
        with self._lock:
            # Re-check the cap: a burst of concurrent creates could have filled
            # it while we were spawning. Over the cap -> drop the just-spawned
            # child rather than exceed the bound.
            over_cap = len(self._sessions) >= self._max
            if not over_cap:
                self._sessions[sid] = _Session(backend, self._now())
        if over_cap:
            # shutdown() (terminate -> wait) runs OUTSIDE the lock so it never
            # serializes other sessions' creation or routing.
            backend.shutdown()
            return None
        return sid, backend

    def get(self, sid: str | None) -> BackendProcess | None:
        """Resolve a session id to its backend, or None if unknown.

        Touches the session's last-activity timestamp so an actively used
        session is never idle-reaped.
        """
        if not sid:
            return None
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is None:
                return None
            sess.last_active = self._now()
            return sess.backend

    def touch(self, sid: str | None) -> None:
        """Mark a session active without resolving it (e.g. on SSE traffic)."""
        if not sid:
            return
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is not None:
                sess.last_active = self._now()

    def remove(self, sid: str | None) -> BackendProcess | None:
        """Detach a session and return its backend (or None if unknown).

        The caller calls ``backend.shutdown()`` OUTSIDE the lock so a slow
        terminate never freezes routing for other sessions.
        """
        if not sid:
            return None
        with self._lock:
            sess = self._sessions.pop(sid, None)
        return sess.backend if sess is not None else None

    def reap_idle(self) -> int:
        """Drop sessions idle past the TTL — or whose child has exited — and
        shut their backends down outside the lock. Returns the count reaped."""
        ttl = self._idle_ttl
        now = self._now()
        victims: list[tuple[str, BackendProcess]] = []
        with self._lock:
            for sid, sess in list(self._sessions.items()):
                if sess.backend.closed or (ttl > 0 and now - sess.last_active > ttl):
                    del self._sessions[sid]
                    victims.append((sid, sess.backend))
        for sid, backend in victims:
            backend.shutdown()
            log(f"reaped idle session {sid[:8]}...")
        return len(victims)

    def shutdown_all(self) -> None:
        """Tear down every session's child (gateway shutdown)."""
        self.stop_reaper()
        with self._lock:
            backends = [s.backend for s in self._sessions.values()]
            self._sessions.clear()
        for backend in backends:
            backend.shutdown()

    def start_reaper(self) -> None:
        """Start the background idle-eviction thread (no-op if TTL disabled)."""
        if self._idle_ttl <= 0 or self._reaper is not None:
            return
        interval = max(1.0, min(self._idle_ttl, _MAX_REAP_INTERVAL_SECS))

        def _loop() -> None:
            while not self._reaper_stop.wait(interval):
                try:
                    self.reap_idle()
                except Exception as e:  # pragma: no cover - defensive
                    log(f"session reaper error: {e}")

        self._reaper = threading.Thread(
            target=_loop, name="session-reaper", daemon=True
        )
        self._reaper.start()

    def stop_reaper(self) -> None:
        self._reaper_stop.set()
        reaper = self._reaper
        if reaper is not None:
            reaper.join(timeout=2)
            self._reaper = None

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._sessions)


# --- embedded OAuth 2.1 Authorization Server (stdlib only, opaque tokens) ---

_AS_METADATA_PATH = "/.well-known/oauth-authorization-server"
_AUTHORIZE_PATH = "/authorize"
_TOKEN_PATH = "/token"
_REGISTER_PATH = "/register"

_AUTH_CODE_TTL_SECS = 60.0
_DEFAULT_ACCESS_TTL_SECS = 3600.0
_REFRESH_TTL_SECS = 60.0 * 60.0 * 24.0 * 30.0  # 30 days
_STORE_CAP = 10000  # per-store entry cap (DoS bound); GC runs before the cap
_CLIENT_CAP = 1000
# Reuse of a just-consumed authorization code / rotated refresh token within
# this window is treated as a benign client retry or concurrent double-submit
# (deny without revoking); a reuse OUTSIDE the window is a theft signal and
# revokes the whole grant family. RFC 9700 Sec. 4.14.2 permits tolerating a
# brief reuse window so a racing/retrying legitimate client is not punished.
_REUSE_GRACE_SECS = 10.0

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
# RFC 7636 Sec. 4.1 code_verifier unreserved set.
_PKCE_VERIFIER_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


def _pkce_s256_challenge(verifier: str) -> str:
    """BASE64URL(SHA256(verifier)) without padding — byte-identical to the
    client's ``oauth.generate_pkce`` so a correct verifier always matches."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _valid_code_verifier(v: str) -> bool:
    return 43 <= len(v) <= 128 and all(c in _PKCE_VERIFIER_CHARS for c in v)


def _redirect_key(uri: str) -> tuple[str, str, str] | None:
    """RFC 8252 loopback redirect key (scheme, host, path), port-agnostic.

    Returns None for anything that is not an ``http://`` loopback URI, or that
    carries a fragment, query, userinfo, or CR/LF. Comparing on this key lets a
    per-run ephemeral callback port still match a registered client_id whose
    stored port differs (step-up reuse). The query is rejected (not just
    ignored): the key drops it, so accepting it would let the raw redirect_uri
    be reflected into a malformed double-``?`` Location and smuggle a second
    identity behind one registered (scheme, host, path).
    """
    if "\r" in uri or "\n" in uri:
        return None
    try:
        p = urlsplit(uri)
    except ValueError:
        return None
    if p.fragment or p.query or p.username or p.password or "@" in p.netloc:
        return None
    host = (p.hostname or "").lower()
    if p.scheme != "http" or host not in _LOOPBACK_HOSTS:
        return None
    return (p.scheme, host, p.path or "/")


def _normalize_public_url(url: str) -> str:
    """Normalize --public-url to a canonical issuer ``scheme://host[:port][/path]``.

    Raises ValueError on a non-http(s) URL, a missing host, userinfo,
    CR/LF/quote/space, a non-loopback ``http://`` (a compliant client refuses
    cleartext non-loopback endpoints), a bad port, or a query/fragment (the
    RFC 8414 Sec. 2 issuer grammar forbids them). The host is lowercased, an
    explicit default port is dropped, an IPv6 literal is re-bracketed, and a
    trailing slash is stripped, so the issuer is byte-identical to what a client
    derives (RFC 8414 Sec. 3.3).

    A PATH component is RETAINED: a path-scoped issuer (``https://host/team-a``)
    lets several ``--enable-oauth`` backends share one host behind a reverse
    proxy, each owning its AS namespace under its own prefix, symmetric with the
    bundled client's RFC 8414 Sec. 3.1 / RFC 9728 Sec. 3.1 path-aware discovery
    (#245). A bare-origin URL (no path) behaves exactly as before.
    """
    if any(c in url for c in ('"', "\r", "\n", " ")):
        raise ValueError("public-url contains forbidden characters")
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("public-url must be an absolute http(s) URL with a host")
    if p.username or p.password or "@" in p.netloc:
        raise ValueError("public-url must not contain userinfo")
    if p.query or p.fragment:
        raise ValueError("public-url must not contain a query or fragment")
    host = p.hostname.lower()
    if p.scheme == "http" and host not in _LOOPBACK_HOSTS:
        raise ValueError("a non-loopback public-url must use https")
    try:
        port = p.port
    except ValueError as e:
        raise ValueError("public-url has an invalid port") from e
    hostpart = f"[{host}]" if ":" in host else host
    default_port = 80 if p.scheme == "http" else 443
    netloc = hostpart if (port is None or port == default_port) else f"{hostpart}:{port}"
    # Retain the path as the issuer prefix; strip only a trailing slash so
    # "https://host/a/" and "https://host/a" canonicalize identically and a bare
    # "https://host/" collapses to the bare origin (unchanged legacy behavior).
    path = p.path.rstrip("/")
    if path:
        # The prefix is concatenated verbatim into the endpoint URLs and the
        # well-known locations, so it MUST be a canonical, traversal-free
        # absolute path: an empty ("//"), "." or ".." segment would be
        # re-normalized differently by a proxy or the client and break the
        # byte-identical-issuer contract (and could escape the intended
        # namespace). Reject rather than silently rewrite. The leading segment
        # is always "" because an authority-form URL path is "/"-rooted.
        segments = path.split("/")
        if segments[0] != "" or any(seg in ("", ".", "..") for seg in segments[1:]):
            raise ValueError(
                "public-url path must be a canonical absolute path "
                "(no empty, '.', or '..' segments)"
            )
    return f"{p.scheme}://{netloc}{path}"


def _redact_query(line: str) -> str:
    """Redact query strings from an access-log line.

    OAuth /authorize requests carry the client's single-use CSRF ``state`` (and
    error redirects can echo it); the bundled client deliberately keeps that
    nonce out of its own logs, so the gateway must not reintroduce it. Every
    ``?...`` run (up to whitespace or a quote) is redacted, covering BOTH the
    origin-form ``/authorize?...`` and the absolute-form
    ``http://host/authorize?...`` request targets (RFC 7230 allows the latter,
    e.g. via a forwarding proxy). MCP requests carry no query, so this is
    lossless here.
    """
    return re.sub(r'\?[^\s"]*', "?<redacted>", line)


class _OAuthProvider:
    """Minimal OAuth 2.1 Authorization Server: DCR + authorization-code + PKCE
    + refresh, with opaque in-memory tokens (no crypto dependency).

    All four stores share one lock; ThreadingHTTPServer serves each request on
    its own thread. ``now`` is injectable so tests can drive TTL expiry without
    sleeping. ``public_url`` (bare origin) pins the issuer; when None the caller
    passes a per-request reflected origin into the metadata builders.
    """

    def __init__(
        self,
        *,
        public_url: str | None,
        trusted_user_header: str | None,
        dev_user: str | None,
        access_ttl: float = _DEFAULT_ACCESS_TTL_SECS,
        code_ttl: float = _AUTH_CODE_TTL_SECS,
        refresh_ttl: float = _REFRESH_TTL_SECS,
        now: Any = time.time,
    ) -> None:
        self.public_url = public_url
        self.trusted_user_header = trusted_user_header
        self.dev_user = dev_user
        self.access_ttl = access_ttl
        self.code_ttl = code_ttl
        self.refresh_ttl = refresh_ttl
        self._now = now
        self._lock = threading.Lock()
        self._clients: dict[str, dict[str, Any]] = {}
        self._codes: dict[str, dict[str, Any]] = {}
        self._access: dict[str, dict[str, Any]] = {}
        self._refresh: dict[str, dict[str, Any]] = {}
        # Tombstones for replay detection (RFC 6749 Sec. 4.1.2 / RFC 9700
        # Sec. 4.14.2): a consumed authorization code or a rotated refresh token
        # is recorded here (token -> {"family", "expires_at"}) so a later replay
        # is detected and the whole token family it minted is revoked. Both are
        # TTL-bounded (GC'd in _gc_locked) and capped like the live stores.
        self._consumed_codes: dict[str, dict[str, Any]] = {}
        self._consumed_refresh: dict[str, dict[str, Any]] = {}

    # -- metadata --------------------------------------------------------

    def metadata(self, issuer: str) -> dict[str, Any]:
        md: dict[str, Any] = {
            "issuer": issuer,
            "authorization_endpoint": issuer + _AUTHORIZE_PATH,
            "token_endpoint": issuer + _TOKEN_PATH,
            "registration_endpoint": issuer + _REGISTER_PATH,
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        }
        # RFC 9207 Sec. 2.3: advertise iss support only when we actually emit it
        # — i.e. for an https issuer, since Sec. 2 requires the iss value to be an
        # https URL. A loopback http dev issuer neither advertises the flag nor
        # sends iss (see authorize()), keeping the two consistent.
        if issuer.startswith("https://"):
            md["authorization_response_iss_parameter_supported"] = True
        return md

    # -- dynamic client registration (RFC 7591) --------------------------

    def register(self, raw: bytes) -> tuple[int, dict[str, Any]]:
        def bad(desc: str) -> tuple[int, dict[str, Any]]:
            return 400, {"error": "invalid_client_metadata", "error_description": desc}

        def bad_redirect(desc: str) -> tuple[int, dict[str, Any]]:
            # RFC 7591 Sec. 3.2.2 defines a dedicated error code for an invalid
            # redirection URI value; prefer it over the generic metadata error.
            return 400, {"error": "invalid_redirect_uri", "error_description": desc}

        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return bad("body must be JSON")
        if not isinstance(body, dict):
            return bad("body must be a JSON object")
        uris = body.get("redirect_uris")
        # RFC 7591 Sec. 3.2.2: a missing / empty / non-array redirect_uris is a
        # STRUCTURAL metadata error (invalid_client_metadata). invalid_redirect_uri
        # is reserved for the case where a present VALUE is invalid (the loopback
        # check below).
        if not isinstance(uris, list) or not uris:
            return bad("redirect_uris must be a non-empty array")
        keys = set()
        for u in uris:
            if not isinstance(u, str) or _redirect_key(u) is None:
                return bad_redirect("redirect_uris must be loopback http URLs")
            keys.add(_redirect_key(u))
        client_id = secrets.token_urlsafe(32)
        now = self._now()
        with self._lock:
            self._recycle_clients_locked()
            if len(self._clients) >= _CLIENT_CAP:
                return bad("registration limit reached")
            self._clients[client_id] = {
                "redirect_keys": keys,
                "redirect_uris": list(uris),
                "created_at": now,
            }
        return 201, {
            "client_id": client_id,
            "redirect_uris": list(uris),
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_id_issued_at": int(now),
        }

    # -- authorization endpoint (RFC 6749 4.1 + RFC 7636) ----------------

    def authorize(
        self, params: dict[str, str], user: str | None, issuer: str
    ) -> dict[str, str]:
        """Return an instruction dict for the handler.

        ``{"kind": "bad_request", "message": ...}`` -> direct 400 (NO redirect,
        per RFC 6749 4.1.2.1 for client_id/redirect_uri errors).
        ``{"kind": "redirect", "location": ...}`` -> 302 (success, or an in-band
        error whose Location carries error= + the echoed state).

        ``issuer`` is the effective AS issuer; an https issuer is echoed back as
        the RFC 9207 ``iss`` parameter on every redirect (mix-up defence).
        """
        cid = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        with self._lock:
            client = self._clients.get(cid)
        if not cid or client is None:
            return {"kind": "bad_request", "message": "unknown or missing client_id"}
        rk = _redirect_key(redirect_uri)
        if rk is None or rk not in client["redirect_keys"]:
            return {"kind": "bad_request", "message": "invalid redirect_uri"}

        state = params.get("state", "")

        def redirect(query: dict[str, str]) -> dict[str, str]:
            if state:
                query = {**query, "state": state}
            # RFC 9207 Sec. 2: include the issuer identifier in BOTH success and
            # error authorization responses so a client talking to multiple ASes
            # can detect a mix-up attack. Sec. 2 requires an https value, so a
            # loopback http dev issuer is left without iss (and metadata() omits
            # the support flag to match). Placed after state so a hostile state
            # cannot shadow it (urlencode emits both verbatim regardless).
            if issuer.startswith("https://"):
                query = {**query, "iss": issuer}
            return {"kind": "redirect", "location": redirect_uri + "?" + urlencode(query)}

        if params.get("response_type") != "code":
            return redirect({"error": "unsupported_response_type"})
        challenge = params.get("code_challenge", "")
        if not challenge:
            return redirect(
                {"error": "invalid_request", "error_description": "code_challenge required"}
            )
        if params.get("code_challenge_method") != "S256":
            return redirect(
                {"error": "invalid_request", "error_description": "code_challenge_method must be S256"}
            )
        if not user:
            # Fail closed: never mint a code for an empty/anonymous user.
            return redirect(
                {"error": "access_denied", "error_description": "no authenticated user"}
            )
        code = secrets.token_urlsafe(32)
        now = self._now()
        with self._lock:
            if len(self._codes) >= _STORE_CAP:
                self._gc_locked()
                self._evict_to_capacity_locked(self._codes, _STORE_CAP)
            self._codes[code] = {
                "client_id": cid,
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "user": user,
                "scope": params.get("scope", ""),
                "resource": params.get("resource"),
                "expires_at": now + self.code_ttl,
            }
        return redirect({"code": code})

    # -- token endpoint (RFC 6749 + RFC 7636) ----------------------------

    def token(self, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
        grant = form.get("grant_type")
        if grant == "authorization_code":
            return self._token_auth_code(form)
        if grant == "refresh_token":
            return self._token_refresh(form)
        if not grant:
            # RFC 6749 Sec. 5.2: a missing required parameter is invalid_request,
            # not unsupported_grant_type (which is for an unrecognized value).
            return 400, {"error": "invalid_request", "error_description": "missing grant_type"}
        return 400, {"error": "unsupported_grant_type"}

    def _token_auth_code(self, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
        code = form.get("code", "")
        if not code:
            return 400, {"error": "invalid_request", "error_description": "missing code"}
        now = self._now()
        with self._lock:
            # Single-use: POP before validating so a replay / concurrent
            # double-POST sees None and cannot mint a second token.
            entry = self._codes.pop(code, None)
            replay_family: str | None = None
            replay_detected = False
            if entry is None:
                # RFC 6749 Sec. 4.1.2: a code used more than once MUST be denied
                # AND SHOULD revoke the tokens previously issued from it. A live
                # tombstone (set on successful issuance below) marks a real
                # reuse; outside the grace window it is a theft signal and we
                # revoke the family. Within the window it is a benign retry /
                # concurrent double-submit, so deny without revoking (falls
                # through to the plain denial). A code that never issued a token
                # (failed validation) leaves no tombstone — plain denial too.
                tomb = self._consumed_codes.get(code)
                if (
                    tomb is not None
                    and tomb["expires_at"] >= now
                    and now - tomb["consumed_at"] > _REUSE_GRACE_SECS
                ):
                    replay_detected = True
                    replay_family = tomb["family"]
                    self._revoke_family_locked(replay_family)
        if entry is None:
            if replay_detected:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "authorization code already used; issued tokens revoked",
                }
            return 400, {"error": "invalid_grant", "error_description": "unknown or used code"}
        if entry["expires_at"] < now:
            return 400, {"error": "invalid_grant", "error_description": "code expired"}
        if form.get("client_id") != entry["client_id"]:
            return 400, {"error": "invalid_grant", "error_description": "client_id mismatch"}
        if form.get("redirect_uri") != entry["redirect_uri"]:
            return 400, {"error": "invalid_grant", "error_description": "redirect_uri mismatch"}
        verifier = form.get("code_verifier", "")
        if not _valid_code_verifier(verifier):
            return 400, {"error": "invalid_request", "error_description": "invalid code_verifier"}
        if not hmac.compare_digest(_pkce_s256_challenge(verifier), entry["code_challenge"]):
            return 400, {"error": "invalid_grant", "error_description": "PKCE verification failed"}
        # Start a new grant family keyed by the code; tombstone the code under
        # the issue lock so a subsequent replay is detected and revoked.
        return self._issue(
            entry["user"], entry["client_id"], entry["scope"], entry["resource"],
            family=code, consumed_code=code,
        )

    def _token_refresh(self, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
        rt = form.get("refresh_token", "")
        if not rt:
            return 400, {"error": "invalid_request", "error_description": "missing refresh_token"}
        now = self._now()
        with self._lock:
            # Validate BEFORE mutating: only consume (rotate) the token once it
            # passes. A wrong/blank client_id must NOT destroy an otherwise-valid
            # 30-day token. Single-use still holds because the successful delete
            # happens under this same lock, so a concurrent double-submit of the
            # same valid token finds None on the second pass.
            entry = self._refresh.get(rt)
            if entry is None:
                # RFC 9700 Sec. 4.14.2: a replay of an already-rotated refresh
                # token OUTSIDE the grace window is a theft signal — revoke the
                # whole family so the attacker AND the racing legitimate client
                # are both cut off (the client re-runs the flow). WITHIN the
                # window it is a benign retry / concurrent double-submit: deny
                # without revoking so the winner's freshly-rotated tokens
                # survive. A token that never existed stays a plain "unknown".
                tomb = self._consumed_refresh.get(rt)
                if tomb is not None and tomb["expires_at"] >= now:
                    if now - tomb["consumed_at"] > _REUSE_GRACE_SECS:
                        self._revoke_family_locked(tomb["family"])
                        return 400, {
                            "error": "invalid_grant",
                            "error_description": "refresh token reuse detected; token family revoked",
                        }
                    return 400, {
                        "error": "invalid_grant",
                        "error_description": "refresh_token already rotated",
                    }
                return 400, {"error": "invalid_grant", "error_description": "unknown refresh_token"}
            if entry["expires_at"] < now:
                del self._refresh[rt]
                return 400, {"error": "invalid_grant", "error_description": "refresh_token expired"}
            if form.get("client_id") != entry["client_id"]:
                return 400, {"error": "invalid_grant", "error_description": "client_id mismatch"}
            family = entry.get("family")
            # Rotate: tombstone the spent token (instead of a plain delete) so a
            # later replay of THIS value is detected as reuse above.
            del self._refresh[rt]
            self._consumed_refresh[rt] = {
                "family": family, "consumed_at": now,
                "expires_at": now + self.refresh_ttl,
            }
        return self._issue(
            entry["user"], entry["client_id"], entry["scope"], entry["resource"],
            family=family,
        )

    def _issue(
        self,
        user: str,
        client_id: str,
        scope: str,
        resource: str | None,
        *,
        family: str | None = None,
        consumed_code: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Mint an access + refresh token pair.

        ``family`` tags both tokens so a later replay of the authorization code
        or a rotated refresh token can revoke the entire grant (see
        _revoke_family_locked). ``consumed_code``, when set, tombstones the
        just-spent authorization code under the same lock so a replay is
        detectable without a separate critical section.
        """
        now = self._now()
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        with self._lock:
            stores = (
                self._access, self._refresh,
                self._consumed_codes, self._consumed_refresh,
            )
            if any(len(s) >= _STORE_CAP for s in stores):
                self._gc_locked()
                for s in stores:
                    self._evict_to_capacity_locked(s, _STORE_CAP)
            self._access[access] = {
                "user": user, "client_id": client_id, "scope": scope,
                "resource": resource, "family": family,
                "expires_at": now + self.access_ttl,
            }
            self._refresh[refresh] = {
                "user": user, "client_id": client_id, "scope": scope,
                "resource": resource, "family": family,
                "expires_at": now + self.refresh_ttl,
            }
            if consumed_code is not None:
                self._consumed_codes[consumed_code] = {
                    "family": family, "consumed_at": now,
                    "expires_at": now + self.refresh_ttl,
                }
        body: dict[str, Any] = {
            "access_token": access,
            "token_type": "Bearer",
            # Positive finite int strictly below the server TTL.
            "expires_in": max(1, int(self.access_ttl) - 1),
            "refresh_token": refresh,
        }
        if scope:
            body["scope"] = scope
        return 200, body

    # -- resource-server validation --------------------------------------

    def validate_access_token(
        self, token: str, expected_resource: str | None = None
    ) -> bool:
        """True if ``token`` is a live issued access token for this resource.

        Beyond the lookup + expiry check, this enforces the RFC 8707 / MCP
        audience binding: when the token was minted for a specific ``resource``
        and the caller passes the resource it is guarding, the two MUST match —
        a token issued for a different audience is rejected even though it is
        otherwise live. A token with no resource binding (``None``) stays
        accepted (lenient), as does a call that does not supply an expected
        resource.
        """
        if not token:
            return False
        now = self._now()
        with self._lock:
            entry = self._access.get(token)
            if entry is None:
                return False
            if entry["expires_at"] < now:
                del self._access[token]
                return False
            tok_resource = entry.get("resource")
            if (
                tok_resource is not None
                and expected_resource is not None
                and tok_resource.rstrip("/") != expected_resource.rstrip("/")
            ):
                return False
            return True

    def _evict_to_capacity_locked(self, store: dict[str, dict[str, Any]], cap: int) -> None:
        """Hard-bound a TTL store: if still at the cap after GC, evict the
        soonest-expiring entries to make room. GC alone frees nothing when every
        entry is still live, so without this the cap is not a real bound."""
        overflow = len(store) - (cap - 1)
        if overflow <= 0:
            return
        victims = sorted(store.items(), key=lambda kv: kv[1]["expires_at"])
        for k, _ in victims[:overflow]:
            del store[k]

    def _gc_locked(self) -> None:
        now = self._now()
        for store in (
            self._codes, self._access, self._refresh,
            self._consumed_codes, self._consumed_refresh,
        ):
            for k in [k for k, v in store.items() if v["expires_at"] < now]:
                del store[k]

    def _revoke_family_locked(self, family: str | None) -> None:
        """Revoke every live access/refresh token in a grant family.

        Called on a detected authorization-code or refresh-token replay
        (RFC 6749 Sec. 4.1.2 / RFC 9700 Sec. 4.14.2). A ``None`` family (a token
        minted before family tagging, or a code that never issued a token) is a
        no-op. The caller already holds ``self._lock``.
        """
        if family is None:
            return
        for store in (self._access, self._refresh):
            for k in [k for k, v in store.items() if v.get("family") == family]:
                del store[k]

    def _recycle_clients_locked(self) -> None:
        # Clients carry no TTL: recycle the oldest at the cap so /register never
        # permanently bricks (evict down to cap-1 to leave room for one insert).
        # Called ONLY from register() so token-issuance GC never evicts a client
        # that is not under registration pressure.
        if len(self._clients) >= _CLIENT_CAP:
            oldest = sorted(self._clients.items(), key=lambda kv: kv[1]["created_at"])
            for k, _ in oldest[: len(self._clients) - (_CLIENT_CAP - 1)]:
                del self._clients[k]


class _Handler(BaseHTTPRequestHandler):
    """Streamable HTTP MCP endpoint backed by a per-session stdio child.

    Class attributes ``registry`` and ``mcp_path`` are bound by
    :func:`build_server` before the server loop starts. The session id for the
    request in flight is held in the per-request instance attribute
    ``_session_id`` (reset at the top of each verb handler), so response
    helpers can echo it — or omit it for errors raised before a session is
    resolved.
    """

    registry: SessionRegistry
    mcp_path: str
    # None disables authentication. A non-None value enables the
    # static-bearer-token Resource Server gate.
    auth_token: str | None = None
    # None disables the embedded OAuth AS. A provider enables it:
    # /authorize /token /register + AS metadata + issued-token RS validation.
    oauth: _OAuthProvider | None = None

    # Quieter, consistent logging: route BaseHTTPRequestHandler's access log
    # through the project logger instead of stderr's default apache-style line.
    def log_message(self, fmt: str, *args: Any) -> None:
        # Redact query strings (OAuth state / code never belong in shared logs).
        log("http: " + _redact_query(fmt % args))

    protocol_version = "HTTP/1.1"

    def _send_json(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        sid = getattr(self, "_session_id", None)
        if sid is not None:
            self.send_header("Mcp-Session-Id", sid)
        self.end_headers()
        self.wfile.write(data)

    def _send_empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        sid = getattr(self, "_session_id", None)
        if sid is not None:
            self.send_header("Mcp-Session-Id", sid)
        self.end_headers()

    def _send_oauth_json(self, status: int, body: str, *, no_store: bool = False) -> None:
        """JSON response for OAuth endpoints (no Mcp-Session-Id header).

        ``no_store`` adds the RFC 6749 Sec. 5.1/5.2 cache headers required on
        token-endpoint responses.
        """
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if no_store:
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _effective_issuer(self) -> str:
        """The pinned --public-url origin, else the (reflected) request origin.

        Drives the AS metadata issuer + endpoint URLs and the PRM
        authorization_servers/resource so all three are byte-stable per request.
        """
        if self.oauth is not None and self.oauth.public_url:
            return self.oauth.public_url
        return self._origin()

    def _issuer_origin_and_prefix(self) -> tuple[str, str]:
        """Split the effective issuer into (bare origin, path prefix).

        The prefix is ``""`` for a bare-origin issuer (the legacy behavior and
        the reflected-Host fallback) and e.g. ``"/team-a"`` for a path-scoped
        ``--public-url``. It drives the root-inserted well-known locations and
        the prefixed AS endpoint / MCP paths so a path-scoped issuer is
        byte-symmetric with the bundled client's RFC 8414 Sec. 3.1 / RFC 9728
        Sec. 3.1 construction (#245). The path prefix can only come from a pinned
        ``--public-url``; the reflected ``_origin()`` never carries one.
        """
        parsed = urlsplit(self._effective_issuer())
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return origin, parsed.path

    def _mcp_wire_path(self) -> str:
        """The on-the-wire MCP path: the issuer prefix + the configured path.

        Behind a path-multiplexing proxy the backend receives the full prefixed
        path (e.g. ``/team-a/mcp``); a bare-origin issuer leaves it ``/mcp``.
        """
        _, prefix = self._issuer_origin_and_prefix()
        return prefix + self.mcp_path

    def _wrong_path(self) -> bool:
        # Compare only the path component; ignore any query string.
        path = self.path.split("?", 1)[0]
        if path != self._mcp_wire_path():
            self._send_json(404, _error_body("not found"))
            return True
        return False

    # --- static-bearer-token Resource Server + RFC 9728 metadata ---

    def _origin(self) -> str:
        """Absolute ``scheme://host`` for building metadata URLs.

        Honors a fronting reverse proxy via ``X-Forwarded-Proto`` /
        ``X-Forwarded-Host`` (the gateway is designed to run behind one), then
        the ``Host`` header, then the bound socket. The host is sanitized so a
        hostile value cannot inject into the quoted challenge / JSON body.
        """
        proto = (
            self.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower()
        )
        if proto not in ("http", "https"):
            proto = "http"
        host = self.headers.get("X-Forwarded-Host", "").split(",")[0].strip()
        if not host:
            host = self.headers.get("Host", "").strip()
        host = _sanitize_host(host)
        if not host:
            addr = self.server.server_address
            host = f"{addr[0]}:{addr[1]}"
        return f"{proto}://{host}"

    def _resource_url(self) -> str:
        return self._effective_issuer() + self.mcp_path

    def _prm_url(self) -> str:
        # RFC 9728 Sec. 3.1 path insertion: the well-known label is inserted
        # between the host and the resource's FULL path (issuer prefix +
        # mcp_path), so a path-scoped issuer yields e.g.
        # https://host/.well-known/oauth-protected-resource/team-a/mcp — byte-
        # symmetric with the client's _build_well_known_url. For a bare-origin
        # issuer (prefix "") this is identical to the legacy form. The 401 hint,
        # the PRM document, and the AS metadata thus all stay consistent (#245).
        origin, prefix = self._issuer_origin_and_prefix()
        return origin + _PRM_WELL_KNOWN_PREFIX + prefix + self.mcp_path

    def _authorized(self) -> bool:
        """True when no auth is configured, or a valid Bearer token is presented.

        Precedence: the static token is checked first (constant-time, exempt
        from expiry), then an issued access token (lookup + expiry). The
        endpoint is open only when NEITHER mechanism is configured.
        """
        auth = self.headers.get("Authorization", "")
        prefix = "Bearer "
        token = auth[len(prefix):] if auth.startswith(prefix) else ""
        if (
            self.auth_token is not None
            and token
            and hmac.compare_digest(token.encode("utf-8"), self.auth_token.encode("utf-8"))
        ):
            return True
        if (
            self.oauth is not None
            and token
            and self.oauth.validate_access_token(token, self._resource_url())
        ):
            return True
        return self.auth_token is None and self.oauth is None

    def _require_auth(self) -> bool:
        """Return True if the request may proceed; else send 401 and return False."""
        if self._authorized():
            return True
        # RFC 6750 Sec. 3 / 3.1: when the request CARRIED a bearer token that
        # failed validation (wrong, expired, revoked, or wrong audience), the
        # challenge SHOULD carry error="invalid_token". When NO token was
        # presented, omit the error attribute — the bare challenge is how the
        # client discovers how to authenticate (adding error there would be a
        # spec violation). RFC 9728 Sec. 5.1: always include the
        # resource_metadata pointer.
        token_presented = self.headers.get("Authorization", "").startswith("Bearer ")
        params = []
        if token_presented:
            params.append('error="invalid_token"')
            params.append(
                'error_description="the access token is expired, revoked, malformed, '
                'or issued for another resource"'
            )
        params.append(f'resource_metadata="{self._prm_url()}"')
        challenge = "Bearer " + ", ".join(params)
        msg = "invalid access token" if token_presented else "authentication required"
        body = _error_body(msg).encode("utf-8")
        self.send_response(401)
        self.send_header("WWW-Authenticate", challenge)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def _serve_prm(self) -> None:
        """Serve RFC 9728 Protected Resource Metadata when any auth is enabled.

        ``authorization_servers`` is added ONLY when the embedded AS is on;
        a static-token-only deployment omits it.
        """
        if self.auth_token is None and self.oauth is None:
            self._send_json(404, _error_body("not found"))
            return
        body: dict[str, Any] = {"resource": self._resource_url()}
        if self.oauth is not None:
            body["authorization_servers"] = [self._effective_issuer()]
        body["bearer_methods_supported"] = ["header"]
        self._send_json(200, json.dumps(body))

    # --- embedded OAuth AS endpoint handlers ---

    def _serve_as_metadata(self) -> None:
        """RFC 8414 Authorization Server Metadata."""
        self._send_oauth_json(200, json.dumps(self.oauth.metadata(self._effective_issuer())))

    def _resolve_user(self) -> str | None:
        """Identify the end user for /authorize. Fails closed.

        Reads the operator-opted-in trusted header (set by a fronting proxy that
        performed the real login), else falls back to --dev-user. With neither,
        returns None and /authorize denies — never an anonymous user. The header
        is trusted ONLY when --trusted-user-header is explicitly configured.
        """
        prov = self.oauth
        if prov.trusted_user_header:
            val = self.headers.get(prov.trusted_user_header, "")
            val = val.strip()
            if val and "\r" not in val and "\n" not in val and len(val) <= 256:
                return val
        return prov.dev_user or None

    def _handle_register(self, raw: bytes) -> None:
        status, body = self.oauth.register(raw)
        # RFC 7591 Sec. 3.2.1's response example carries Cache-Control: no-store;
        # send it for symmetry with the token endpoint (and in case a future
        # registration response ever carries a credential).
        self._send_oauth_json(status, json.dumps(body), no_store=True)

    def _handle_token(self, raw: bytes) -> None:
        try:
            parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
            form = {k: v[0] for k, v in parsed.items()}
        except (UnicodeDecodeError, ValueError):
            self._send_oauth_json(
                400, json.dumps({"error": "invalid_request"}), no_store=True
            )
            return
        status, body = self.oauth.token(form)
        self._send_oauth_json(status, json.dumps(body), no_store=True)

    def _handle_authorize(self) -> None:
        query = urlsplit(self.path).query
        parsed = parse_qs(query, keep_blank_values=True)
        params = {k: v[0] for k, v in parsed.items()}
        user = self._resolve_user()
        result = self.oauth.authorize(params, user, self._effective_issuer())
        if result["kind"] == "bad_request":
            self._send_oauth_json(
                400,
                json.dumps(
                    {"error": "invalid_request", "error_description": result["message"]}
                ),
            )
            return
        # 302 to the validated redirect_uri (Location built via urlencode and a
        # CR/LF-free, registered loopback redirect_uri — no injection surface).
        self.send_response(302)
        self.send_header("Location", result["location"])
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _resolve_session(self, req_id: Any = None) -> BackendProcess | None:
        """Resolve the request's session, or emit the spec error and return None.

        A missing ``Mcp-Session-Id`` -> 400 (MCP spec item 2); an unknown or
        terminated id -> 404 (item 3, which drives the client's re-initialize).
        On success records the id for the response header and returns the
        backend. Shared by the POST (non-initialize) and GET paths so both
        report the same status for the same condition.
        """
        sid = self.headers.get("Mcp-Session-Id")
        if not sid:
            self._send_json(400, _error_body("Mcp-Session-Id required", req_id))
            return None
        backend = self.registry.get(sid)
        if backend is None:
            self._send_json(404, _error_body("unknown or expired session", req_id))
            return None
        self._session_id = sid
        return backend

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        # Reset the per-request session id (the handler instance is reused
        # across keep-alive requests); responses before resolution omit it.
        self._session_id = None
        # Read (drain) the request body BEFORE any early return. On HTTP/1.1
        # keep-alive, leaving an unread body in the socket makes the handler
        # parse those leftover bytes as the next request line ("Bad request
        # syntax"). So the path / parse-error branches below run only after the
        # body is consumed.
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0:
                raise ValueError
        except ValueError:
            # Unknown body length -> we cannot safely drain it; don't reuse the
            # connection.
            self.close_connection = True
            self._send_json(400, _error_body("invalid Content-Length"))
            return
        raw = self.rfile.read(length) if length > 0 else b""
        if self.oauth is not None:
            # AS POST endpoints (DCR + token) bootstrap the token, exempt from
            # the RS gate. Match by EXACT path under the issuer prefix (empty for
            # a bare-origin issuer). Body already drained above.
            path = self.path.split("?", 1)[0]
            _, prefix = self._issuer_origin_and_prefix()
            if path == prefix + _REGISTER_PATH:
                self._handle_register(raw)
                return
            if path == prefix + _TOKEN_PATH:
                self._handle_token(raw)
                return
        if self._wrong_path():
            return
        if not self._require_auth():
            return
        try:
            text = raw.decode("utf-8")
            msg = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, _error_body("invalid JSON"))
            return

        kind = _classify(msg)
        if kind not in ("request", "notification", "response"):
            # Batches and malformed payloads are out of scope here.
            self._send_json(400, _error_body("unsupported or invalid message"))
            return
        req_id = msg.get("id") if kind == "request" else None
        if kind == "request":
            # A JSON-RPC id is a String, Number, or null. A non-scalar id
            # (object / array) is malformed AND unhashable, so using it as the
            # pending-response dict key would raise TypeError and crash the
            # handler thread — reject it up front, mirroring relay's
            # _extract_cancel_id guard and the never-crash invariant.
            if req_id is not None and not isinstance(req_id, (str, int, float)):
                self._send_json(400, _error_body("invalid JSON-RPC id"))
                return

        # --- session resolution (MCP Streamable HTTP session management) ---
        is_init = kind == "request" and msg.get("method") == "initialize"
        if is_init:
            # `initialize` starts a session (MCP spec item 1): spawn a fresh
            # child and mint an id, returned via the Mcp-Session-Id response
            # header. A presented (stale) id is dropped first.
            stale_id = self.headers.get("Mcp-Session-Id")
            if stale_id:
                stale = self.registry.remove(stale_id)
                if stale is not None:
                    stale.shutdown()
            created = self.registry.create()
            if created is None:
                self._send_json(503, _error_body("session limit reached", req_id))
                return
            self._session_id, backend = created
        else:
            # MCP spec items 2/3: sessionless -> 400, unknown/terminated -> 404.
            backend = self._resolve_session(req_id)
            if backend is None:
                return

        if kind == "request":
            if backend.closed:
                # Dead child: drop the session so the slot is reclaimed and the
                # client's next request re-initializes (404) instead of looping
                # on 503. shutdown() reaps the already-exited child.
                stale = self.registry.remove(self._session_id)
                if stale is not None:
                    stale.shutdown()
                self._send_json(503, _error_body("backend unavailable", req_id))
                return
            line = backend.send_request(
                json.dumps(msg), req_id, _BACKEND_RESPONSE_TIMEOUT_SECS
            )
            if line is None:
                if is_init:
                    # The freshly-spawned child never answered initialize, so it
                    # never became a usable session — don't leak its slot/child.
                    stale = self.registry.remove(self._session_id)
                    if stale is not None:
                        stale.shutdown()
                self._send_json(
                    504, _error_body("no response from backend", req_id)
                )
                return
            self._send_json(200, line)
        else:
            # Fire-and-forget toward the backend; the MCP spec returns 202 for
            # a POST that carries no request needing a reply.
            backend.send_oneway(json.dumps(msg))
            self._send_empty(202)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._session_id = None
        path = self.path.split("?", 1)[0]
        # RFC 9728 metadata is unauthenticated — it is how the client discovers
        # how to authenticate — so it is checked before the auth gate. Match the
        # exact well-known path or a path-suffixed form (".../<resource path>"),
        # NOT a mere prefix (so "...-resource-evil" does not match).
        if path == _PRM_WELL_KNOWN_PREFIX or path.startswith(
            _PRM_WELL_KNOWN_PREFIX + "/"
        ):
            self._serve_prm()
            return
        if self.oauth is not None:
            # AS endpoints bootstrap the token, so they are exempt from the RS
            # gate. The AS metadata sits at the RFC 8414 Sec. 3.1 root-inserted
            # location (well-known label + issuer prefix); /authorize lives under
            # the prefix. Both reduce to the legacy root paths when the prefix is
            # empty. Match by EXACT path (never a loose prefix).
            origin, prefix = self._issuer_origin_and_prefix()
            if path == _AS_METADATA_PATH + prefix:
                self._serve_as_metadata()
                return
            if path == prefix + _AUTHORIZE_PATH:
                self._handle_authorize()
                return
        if self._wrong_path():
            return
        if not self._require_auth():
            return
        # The SSE stream carries a session's server-initiated messages, so it
        # must name an existing session: sessionless -> 400, unknown/terminated
        # -> 404 (drives the client's re-initialize), as on the POST path.
        backend = self._resolve_session()
        if backend is None:
            return
        # Open an SSE stream carrying server-initiated messages (notifications
        # and server->client requests) until the client disconnects or the
        # backend dies. The stream has no Content-Length and is not chunked, so
        # mark the connection close-delimited (unambiguous framing): the body
        # ends when we close it, never reused for a follow-up request.
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("Mcp-Session-Id", self._session_id)
        self.end_headers()
        q = backend.server_initiated
        try:
            while not backend.closed:
                # An open SSE stream is activity: keep the session warm so the
                # idle reaper does not evict a connected-but-quiet client.
                self.registry.touch(self._session_id)
                try:
                    line = q.get(timeout=_SSE_KEEPALIVE_SECS)
                except queue.Empty:
                    # SSE comment keepalive — also how we notice backend death.
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                payload = f"data: {line}\n\n".encode("utf-8")
                self.wfile.write(payload)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ValueError):
            # Client went away mid-stream — normal, not an error.
            return

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        # MCP clients DELETE the endpoint to terminate a session (spec item 5).
        # Tear down that session's backend child.
        self._session_id = None
        if self._wrong_path():
            return
        if not self._require_auth():
            return
        sid_header = self.headers.get("Mcp-Session-Id")
        if not sid_header:
            self._send_json(400, _error_body("Mcp-Session-Id required"))
            return
        backend = self.registry.remove(sid_header)
        if backend is None:
            self._send_json(404, _error_body("unknown or expired session"))
            return
        # shutdown() (terminate -> wait) runs after the dict pop, off the lock.
        backend.shutdown()
        log(f"session {sid_header[:8]}... terminated by client")
        self._session_id = sid_header
        self._send_empty(200)


def build_server(
    command: list[str],
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    mcp_path: str = "/mcp",
    auth_token: str | None = None,
    oauth: _OAuthProvider | None = None,
    max_sessions: int = _DEFAULT_MAX_SESSIONS,
    idle_ttl: float = 0.0,
) -> tuple[ThreadingHTTPServer, SessionRegistry]:
    """Construct the HTTP server and session registry without running the loop.

    Separated from :func:`serve` so tests can drive the server on an ephemeral
    port (``port=0``) without installing signal handlers or blocking. The
    caller owns the lifecycle: run ``httpd.serve_forever()`` (typically in a
    thread), then ``registry.shutdown_all()`` + ``httpd.server_close()``.

    ``auth_token`` (when not None) enables the static-bearer-token Resource
    Server gate. ``oauth`` (when not None) enables the embedded OAuth
    Authorization Server: /authorize /token /register + AS metadata, and
    the RS gate then also accepts issued access tokens. ``idle_ttl`` (when
    ``> 0``) arms idle session eviction; the caller starts the reaper with
    ``registry.start_reaper()``.
    """
    registry = SessionRegistry(
        command, max_sessions=max_sessions, idle_ttl=idle_ttl
    )
    handler = type(
        "_BoundHandler",
        (_Handler,),
        {
            "registry": registry,
            "mcp_path": mcp_path,
            "auth_token": auth_token,
            "oauth": oauth,
        },
    )
    httpd = ThreadingHTTPServer((host, port), handler)
    # Don't let the process hang on lingering SSE handler threads at shutdown.
    httpd.daemon_threads = True
    return httpd, registry


def serve(
    command: list[str],
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    mcp_path: str = "/mcp",
    auth_token: str | None = None,
    oauth: _OAuthProvider | None = None,
    max_sessions: int = _DEFAULT_MAX_SESSIONS,
    idle_ttl: float = 0.0,
) -> None:
    """Run the reverse gateway until interrupted.

    Spawns ``command`` as the backend stdio MCP server and serves it at
    ``http://host:port{mcp_path}``. Blocks until SIGINT/SIGTERM, then tears
    the backend down. ``auth_token`` enables the static-token gate;
    ``oauth`` enables the embedded Authorization Server. ``max_sessions`` caps
    concurrent sessions; ``idle_ttl`` (when ``> 0``) evicts idle sessions.
    """
    httpd, registry = build_server(
        command,
        host=host,
        port=port,
        mcp_path=mcp_path,
        auth_token=auth_token,
        oauth=oauth,
        max_sessions=max_sessions,
        idle_ttl=idle_ttl,
    )
    registry.start_reaper()

    stopping = threading.Event()

    def _stop(_signum: int, _frame: Any) -> None:
        if stopping.is_set():
            return
        stopping.set()
        log("shutting down")
        # shutdown() must run off the handler/main thread; spawn a stopper.
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    modes = []
    if auth_token:
        modes.append("static bearer token")
    if oauth is not None:
        modes.append("embedded OAuth AS")
    auth_state = " + ".join(modes) if modes else "no auth"
    ttl_state = f"idle-ttl {idle_ttl:g}s" if idle_ttl > 0 else "no idle eviction"
    log(
        f"serving {' '.join(command)} at "
        f"http://{host}:{port}{mcp_path} ({auth_state}; "
        f"max {max_sessions} sessions, {ttl_state})"
    )
    try:
        httpd.serve_forever()
    finally:
        registry.shutdown_all()
        httpd.server_close()


def serve_main(argv: list[str]) -> None:
    """Entry point for the ``mcp-stdio serve`` subcommand.

    Usage: ``mcp-stdio serve [--host H] [--port P] [--path /mcp] -- CMD [ARG...]``
    The backend command is everything after the gateway options (an optional
    ``--`` separator is supported and stripped).
    """
    parser = argparse.ArgumentParser(
        prog="mcp-stdio serve",
        description=(
            "Expose a local stdio MCP server as a Streamable HTTP MCP endpoint. "
            "Optionally protect it with a static bearer token. The backend "
            "command follows the options."
        ),
    )
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="bind port (default: 8080)")
    parser.add_argument("--path", default="/mcp", help="MCP endpoint path (default: /mcp)")
    parser.add_argument(
        "--auth-token",
        default=None,
        metavar="TOKEN",
        help=(
            "Require this static bearer token on MCP requests "
            f"(or set {_SERVE_TOKEN_ENV}; the env var is preferred since a flag "
            "value is visible in `ps`). Omit for no authentication."
        ),
    )
    parser.add_argument(
        "--enable-oauth",
        action="store_true",
        help=(
            "Enable the embedded OAuth 2.1 Authorization Server (PKCE auth-code, "
            "dynamic client registration, refresh). MCP requests then require an "
            "issued bearer token; the mcp-stdio client's --oauth flow works "
            "against this gateway."
        ),
    )
    parser.add_argument(
        "--public-url",
        default=None,
        metavar="URL",
        help=(
            "Canonical external issuer URL (e.g. https://gw.example.org) used to "
            "pin the OAuth issuer and all endpoint URLs. Strongly recommended "
            "behind a reverse proxy. A PATH is retained as an issuer prefix "
            "(e.g. https://gw.example.org/team-a), letting several "
            "--enable-oauth backends share one host under distinct path "
            "prefixes; the AS endpoints then live under that prefix and the "
            "well-known docs at the RFC 8414/9728 root-inserted locations. A "
            "bare-origin URL behaves as before."
        ),
    )
    parser.add_argument(
        "--trusted-user-header",
        default=None,
        metavar="HEADER",
        help=(
            "Trust this request header as the authenticated user at /authorize "
            "(e.g. X-Forwarded-User). ONLY safe behind a reverse proxy that "
            "STRIPS any client-supplied copy. Off by default (fails closed)."
        ),
    )
    parser.add_argument(
        "--dev-user",
        default=None,
        metavar="USER",
        help=(
            "INSECURE local-testing identity for /authorize when no trusted "
            "header is present. For loopback smoke tests only; never a real "
            "auth boundary."
        ),
    )
    parser.add_argument(
        "--access-token-ttl",
        type=int,
        default=int(_DEFAULT_ACCESS_TTL_SECS),
        metavar="SECONDS",
        help="Issued access-token lifetime in seconds (default: 3600).",
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=_DEFAULT_MAX_SESSIONS,
        metavar="N",
        help=(
            "Maximum concurrent MCP sessions, each backed by its own child "
            f"process (default: {_DEFAULT_MAX_SESSIONS}). An initialize past "
            "the cap gets 503 — a fork-bomb guard for an open gateway."
        ),
    )
    parser.add_argument(
        "--session-idle-ttl",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help=(
            "Evict a session (and its child) after this many seconds with no "
            "activity, so a client that disconnects without DELETE does not "
            "pin a slot. 0 (default) disables idle eviction."
        ),
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="backend stdio MCP server command (after the options)",
    )
    args = parser.parse_args(argv)

    command = list(args.command)
    if command and command[0] == "--":  # tolerate an explicit separator
        command = command[1:]
    if not command:
        parser.error("a backend command is required, e.g. serve -- python -m my_mcp")
    if not args.path.startswith("/"):
        parser.error("--path must start with '/'")
    # The path is reflected into the quoted WWW-Authenticate resource_metadata
    # and the PRM JSON; reject characters that would break that quoting or
    # inject into headers.
    if any(c in args.path for c in ('"', "\r", "\n", " ")):
        parser.error("--path must not contain quotes, spaces, or CR/LF")

    # Env var is preferred (not visible in `ps`); an explicit flag wins but
    # warns. An empty token (flag or exported-but-empty env var) normalizes to
    # None = no auth, rather than enabling an impossible-to-satisfy gate.
    auth_token = args.auth_token
    if auth_token is not None:
        log("warning: --auth-token is visible in `ps`; prefer "
            f"{_SERVE_TOKEN_ENV} for production")
    else:
        auth_token = os.environ.get(_SERVE_TOKEN_ENV)
    if not auth_token:
        auth_token = None

    # --- embedded OAuth AS setup ---
    oauth = None
    if args.dev_user is not None and not args.enable_oauth:
        parser.error("--dev-user requires --enable-oauth")
    if args.trusted_user_header is not None and any(
        c in args.trusted_user_header for c in (" ", "\r", "\n", ":")
    ):
        parser.error("--trusted-user-header must be a valid header name")
    if args.access_token_ttl <= 0:
        parser.error("--access-token-ttl must be > 0")
    if args.max_sessions < 1:
        parser.error("--max-sessions must be >= 1")
    if args.session_idle_ttl < 0:
        parser.error("--session-idle-ttl must be >= 0")
    if args.enable_oauth:
        public_url = None
        if args.public_url is not None:
            try:
                public_url = _normalize_public_url(args.public_url)
            except ValueError as e:
                parser.error(f"--public-url invalid: {e}")
            if public_url != args.public_url.rstrip("/"):
                log(f"note: --public-url normalized to {public_url}")
        else:
            log(
                "warning: --enable-oauth without --public-url; the issuer is "
                "reflected from the request Host. Set --public-url behind a proxy."
            )
        if args.trusted_user_header is None and args.dev_user is None:
            log(
                "warning: --enable-oauth without --trusted-user-header or "
                "--dev-user; /authorize will deny all users (no identity source)."
            )
        if args.dev_user is not None:
            log("warning: --dev-user is INSECURE; for loopback testing only")
        oauth = _OAuthProvider(
            public_url=public_url,
            trusted_user_header=args.trusted_user_header,
            dev_user=args.dev_user,
            access_ttl=float(args.access_token_ttl),
        )

    serve(
        command,
        host=args.host,
        port=args.port,
        mcp_path=args.path,
        auth_token=auth_token,
        oauth=oauth,
        max_sessions=args.max_sessions,
        idle_ttl=args.session_idle_ttl,
    )
