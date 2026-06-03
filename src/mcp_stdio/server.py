"""Reverse gateway: expose a local stdio MCP server as a Streamable HTTP endpoint.

This is the mirror image of :mod:`mcp_stdio.relay`. ``relay`` is the client
side (stdio in, HTTP out); this module is the server side (HTTP in, stdio out):
it spawns a local stdio MCP server as a child process and publishes it as a
Streamable HTTP MCP endpoint, so clients that cannot spawn the server locally
(a laptop without it installed, a remote bot) can reach it over the network.

Milestone M1 (this file): a single backend, **no authentication**. The HTTP
surface implements the MCP Streamable HTTP transport's request/response and
notification semantics plus a GET SSE channel for server-initiated messages.
Authentication (Bearer/JWT validation as a Resource Server, then an embedded
Authorization Server) layers on top in later milestones — see issue #235.

Stdlib only (``http.server`` + ``subprocess`` + ``threading``), matching the
project's httpx-only-runtime constraint: the server path adds no dependency.

Concurrency model: one long-lived backend child speaks newline-delimited
JSON-RPC over its stdin/stdout. A single reader thread drains the child's
stdout and routes each message — a response (id + result/error, no method)
wakes the waiting HTTP handler keyed by the JSON-RPC id; anything
server-initiated (carries ``method``) is queued for the GET SSE stream.

M1 single-client assumption: JSON-RPC ids are passed through verbatim, so two
distinct clients that happen to reuse the same id while sharing one backend
could cross responses. M1 targets one logical client (e.g. one Claude); id
remapping for true multi-client fan-out is a later milestone.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import queue
import signal
import subprocess
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

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
    M1 does not handle).
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
        # consumer. Unbounded queue is acceptable for M1's single client; a
        # later milestone can bound + shed.
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
            # earlier waiter will time out. Acceptable for M1.
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


class _Handler(BaseHTTPRequestHandler):
    """Streamable HTTP MCP endpoint backed by a single stdio child.

    Class attributes ``backend``, ``mcp_path`` and ``session_id`` are bound by
    :func:`serve` before the server loop starts.
    """

    backend: BackendProcess
    mcp_path: str
    session_id: str
    # None disables authentication (M1 behavior). A non-None value enables the
    # static-bearer-token Resource Server gate (M2).
    auth_token: str | None = None

    # Quieter, consistent logging: route BaseHTTPRequestHandler's access log
    # through the project logger instead of stderr's default apache-style line.
    def log_message(self, fmt: str, *args: Any) -> None:
        log("http: " + (fmt % args))

    protocol_version = "HTTP/1.1"

    def _send_json(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Mcp-Session-Id", self.session_id)
        self.end_headers()
        self.wfile.write(data)

    def _send_empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Mcp-Session-Id", self.session_id)
        self.end_headers()

    def _wrong_path(self) -> bool:
        # Compare only the path component; ignore any query string.
        path = self.path.split("?", 1)[0]
        if path != self.mcp_path:
            self._send_json(404, _error_body("not found"))
            return True
        return False

    # --- M2: static-bearer-token Resource Server + RFC 9728 metadata ---

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
        return self._origin() + self.mcp_path

    def _prm_url(self) -> str:
        # RFC 9728 Sec. 3.1 path insertion.
        return self._origin() + _PRM_WELL_KNOWN_PREFIX + self.mcp_path

    def _authorized(self) -> bool:
        """True when auth is disabled or a valid Bearer token is presented."""
        if self.auth_token is None:
            return True
        auth = self.headers.get("Authorization", "")
        prefix = "Bearer "
        token = auth[len(prefix):] if auth.startswith(prefix) else ""
        # Constant-time compare on bytes (str compare_digest rejects non-ASCII).
        return bool(token) and hmac.compare_digest(
            token.encode("utf-8"), self.auth_token.encode("utf-8")
        )

    def _require_auth(self) -> bool:
        """Return True if the request may proceed; else send 401 and return False."""
        if self._authorized():
            return True
        body = _error_body("authentication required").encode("utf-8")
        self.send_response(401)
        # RFC 9728 Sec. 5.1: point the client at the protected-resource metadata.
        self.send_header(
            "WWW-Authenticate", f'Bearer resource_metadata="{self._prm_url()}"'
        )
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def _serve_prm(self) -> None:
        """Serve RFC 9728 Protected Resource Metadata (only when auth is on)."""
        if self.auth_token is None:
            self._send_json(404, _error_body("not found"))
            return
        body = json.dumps(
            {
                "resource": self._resource_url(),
                # No authorization_servers yet: M2 uses operator-issued static
                # tokens. M3's embedded AS adds the issuer here.
                "bearer_methods_supported": ["header"],
            }
        )
        self._send_json(200, body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
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
        if kind == "request":
            req_id = msg.get("id")
            # A JSON-RPC id is a String, Number, or null. A non-scalar id
            # (object / array) is malformed AND unhashable, so using it as the
            # pending-response dict key would raise TypeError and crash the
            # handler thread — reject it up front, mirroring relay's
            # _extract_cancel_id guard and the never-crash invariant.
            if req_id is not None and not isinstance(req_id, (str, int, float)):
                self._send_json(400, _error_body("invalid JSON-RPC id"))
                return
            if self.backend.closed:
                self._send_json(503, _error_body("backend unavailable", req_id))
                return
            line = self.backend.send_request(
                json.dumps(msg), req_id, _BACKEND_RESPONSE_TIMEOUT_SECS
            )
            if line is None:
                self._send_json(
                    504, _error_body("no response from backend", req_id)
                )
                return
            self._send_json(200, line)
        elif kind in ("notification", "response"):
            # Fire-and-forget toward the backend; the MCP spec returns 202 for
            # a POST that carries no request needing a reply.
            self.backend.send_oneway(json.dumps(msg))
            self._send_empty(202)
        else:
            # Batches and malformed payloads are out of scope for M1.
            self._send_json(400, _error_body("unsupported or invalid message"))

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
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
        if self._wrong_path():
            return
        if not self._require_auth():
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
        self.send_header("Mcp-Session-Id", self.session_id)
        self.end_headers()
        q = self.backend.server_initiated
        try:
            while not self.backend.closed:
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
        # MCP clients DELETE the endpoint to end a session. M1 has one
        # long-lived backend, so acknowledge without tearing it down.
        if self._wrong_path():
            return
        if not self._require_auth():
            return
        self._send_empty(200)


def build_server(
    command: list[str],
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    mcp_path: str = "/mcp",
    auth_token: str | None = None,
) -> tuple[ThreadingHTTPServer, BackendProcess]:
    """Construct the HTTP server and backend without running the loop.

    Separated from :func:`serve` so tests can drive the server on an ephemeral
    port (``port=0``) without installing signal handlers or blocking. The
    caller owns the lifecycle: run ``httpd.serve_forever()`` (typically in a
    thread), then ``backend.shutdown()`` + ``httpd.server_close()``.

    ``auth_token`` (when not None) enables the static-bearer-token Resource
    Server gate (M2): MCP-path requests require ``Authorization: Bearer
    <auth_token>`` and a 401 advertises RFC 9728 metadata.
    """
    backend = BackendProcess(command)
    handler = type(
        "_BoundHandler",
        (_Handler,),
        {
            "backend": backend,
            "mcp_path": mcp_path,
            "session_id": uuid.uuid4().hex,
            "auth_token": auth_token,
        },
    )
    httpd = ThreadingHTTPServer((host, port), handler)
    # Don't let the process hang on lingering SSE handler threads at shutdown.
    httpd.daemon_threads = True
    return httpd, backend


def serve(
    command: list[str],
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    mcp_path: str = "/mcp",
    auth_token: str | None = None,
) -> None:
    """Run the reverse gateway until interrupted.

    Spawns ``command`` as the backend stdio MCP server and serves it at
    ``http://host:port{mcp_path}``. Blocks until SIGINT/SIGTERM, then tears
    the backend down. ``auth_token`` enables the static-token gate (M2).
    """
    httpd, backend = build_server(
        command, host=host, port=port, mcp_path=mcp_path, auth_token=auth_token
    )

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

    auth_state = "static bearer token" if auth_token else "no auth"
    log(
        f"serving {' '.join(command)} at "
        f"http://{host}:{port}{mcp_path} ({auth_state})"
    )
    try:
        httpd.serve_forever()
    finally:
        backend.shutdown()
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

    serve(
        command,
        host=args.host,
        port=args.port,
        mcp_path=args.path,
        auth_token=auth_token,
    )
