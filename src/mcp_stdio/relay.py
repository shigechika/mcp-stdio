"""Core relay logic: stdin JSON-RPC -> HTTP POST -> stdout."""

from __future__ import annotations

import email.utils
import json
import math
import re
import signal
import socket
import sys
import threading
import time
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from mcp_stdio import __version__

MAX_RETRIES = 3
RETRY_DELAY = 1  # seconds

# HTTP 429 rate-limit handling. If the server sends ``Retry-After`` we
# honour it up to the cap; beyond the cap we give up rather than make the
# client hang on an unreasonable server-requested wait. Missing
# ``Retry-After`` falls back to the same linear backoff used for
# transient connection errors. Closes the gap called out by
# modelcontextprotocol/typescript-sdk#1892.
_RATE_LIMIT_SLEEP_CAP_SECS = 60.0

# TCP keepalive tuning. Together (60 s idle + 4 × 15 s probes) a silent
# half-open TCP is surfaced as a socket error within ~120 s — fast enough
# to matter during a long tool call, slow enough to tolerate transient
# network blips. Used by ``_tcp_keepalive_socket_options`` below.
_KEEPALIVE_IDLE_SECS = 60
_KEEPALIVE_INTVL_SECS = 15
_KEEPALIVE_CNT = 4


def _tcp_keepalive_socket_options() -> list[tuple[int, int, int]]:
    """Return a cross-platform socket_options list for TCP keepalive.

    Portable baseline: ``SO_KEEPALIVE`` is enabled on every platform that
    supports it. The detailed idle/interval/count tuning uses platform
    branches:

    - **Linux / FreeBSD / NetBSD** — expose ``TCP_KEEPIDLE`` /
      ``TCP_KEEPINTVL`` / ``TCP_KEEPCNT`` via ``socket``. Numeric
      constant values differ across OSes but Python resolves them
      correctly per platform, so the same three tuples apply.
    - **macOS** — ``TCP_KEEPALIVE`` sets the idle time; ``TCP_KEEPINTVL``
      and ``TCP_KEEPCNT`` were added in macOS 10.15 and are used when
      available.
    - **Windows** — per-socket idle/interval tuning requires the
      ``SIO_KEEPALIVE_VALS`` ioctl which httpx's ``socket_options``
      mechanism cannot deliver. We set ``SO_KEEPALIVE`` alone; the
      OS default probe interval (~2 h) still beats the current
      forever-hang on a half-open TCP. Half-open detection under
      Windows requires an out-of-band mechanism (e.g. MCP ``ping``)
      for tighter bounds.

    Always includes ``SO_KEEPALIVE`` so the returned list is never
    empty; callers can therefore treat the absence of a keepalive
    entry as "the caller opted out" rather than "the platform is
    unsupported".
    """
    opts: list[tuple[int, int, int]] = [
        (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
    ]
    plat = sys.platform
    if plat == "linux" or plat.startswith("freebsd") or plat.startswith("netbsd"):
        for name in ("TCP_KEEPIDLE", "TCP_KEEPINTVL", "TCP_KEEPCNT"):
            if not hasattr(socket, name):
                return opts
        opts += [
            (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, _KEEPALIVE_IDLE_SECS),
            (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, _KEEPALIVE_INTVL_SECS),
            (socket.IPPROTO_TCP, socket.TCP_KEEPCNT, _KEEPALIVE_CNT),
        ]
    elif plat == "darwin":
        # TCP_KEEPALIVE is the idle timer on darwin; without it, the
        # interval / count options alone are meaningless. Guard
        # consistently with the Linux branch above.
        if not hasattr(socket, "TCP_KEEPALIVE"):
            return opts
        opts.append(
            (socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, _KEEPALIVE_IDLE_SECS)
        )
        if hasattr(socket, "TCP_KEEPINTVL"):
            opts.append(
                (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, _KEEPALIVE_INTVL_SECS)
            )
        if hasattr(socket, "TCP_KEEPCNT"):
            opts.append((socket.IPPROTO_TCP, socket.TCP_KEEPCNT, _KEEPALIVE_CNT))
    # win32 / cygwin / other: only SO_KEEPALIVE. See docstring.
    return opts


def _make_httpx_transport(*, tcp_keepalive: bool) -> httpx.HTTPTransport:
    """Build the HTTPTransport used by relay clients.

    Injects TCP keepalive socket options unless the caller opted out.
    Isolated as a helper so tests can patch it and both ``run`` and
    ``run_sse`` share the same transport construction.
    """
    socket_options = _tcp_keepalive_socket_options() if tcp_keepalive else None
    return httpx.HTTPTransport(socket_options=socket_options)

# MCP spec defines four paginated list methods. Some clients (notably
# Claude Code, cf. anthropics/claude-code#39586) silently drop pages beyond
# the first; auto-paginating in the gateway hides the bug from callers.
PAGINATED_LIST_METHODS: dict[str, str] = {
    "tools/list": "tools",
    "resources/list": "resources",
    "resources/templates/list": "resourceTemplates",
    "prompts/list": "prompts",
}

# Safety cap for runaway or malicious cursor chains.
MAX_LIST_PAGES = 100


def _enforce_lf_stdio() -> None:
    """Force bare LF line endings on stdin/stdout.

    Python's default ``TextIOWrapper`` on Windows translates ``\\n`` to
    ``\\r\\n`` on output, which corrupts the NDJSON wire format used by
    MCP. A no-op on POSIX where LF is already the default. See
    modelcontextprotocol/python-sdk#2433 for the same class of bug.
    """
    if sys.platform != "win32":
        return
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(newline="")


_enforce_lf_stdio()


def log(msg: str) -> None:
    """Log to stderr (visible in Claude Desktop/Code logs)."""
    print(f"[mcp-stdio] {msg}", file=sys.stderr, flush=True)


# Serializes writes to stdout. ``run_sse`` drives two writers — the SSE
# reader thread (message events via ``_emit``) and the main loop (error
# responses) — and ``print`` is not atomic across the content and its
# trailing newline, so without this lock a POST error coinciding with a
# message event could interleave mid-line and corrupt the NDJSON wire
# format. ``run`` is single-threaded and pays only an uncontended lock.
_STDOUT_LOCK = threading.Lock()


def _write_line(line: str) -> None:
    """Write one line to stdout atomically (content + newline under a lock)."""
    with _STDOUT_LOCK:
        sys.stdout.write(f"{line}\n")
        sys.stdout.flush()


def _extract_id(line: str) -> Any:
    """Extract JSON-RPC id from request line."""
    try:
        return json.loads(line).get("id")
    except (json.JSONDecodeError, AttributeError):
        return None


_DEFAULT_SCHEME_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def _same_origin(url_a: str, url_b: str) -> bool:
    """Return True if two URLs share an RFC 6454 origin (scheme/host/port)."""
    try:
        a, b = urlsplit(url_a), urlsplit(url_b)
        oa = (a.scheme, (a.hostname or "").lower(),
              a.port if a.port is not None else _DEFAULT_SCHEME_PORTS.get(a.scheme))
        ob = (b.scheme, (b.hostname or "").lower(),
              b.port if b.port is not None else _DEFAULT_SCHEME_PORTS.get(b.scheme))
    except ValueError:
        return False
    return oa == ob


# MCP-Protocol-Version header (spec rev 2025-06-18, "Protocol Version Header").
# After initialization the client MUST send the negotiated protocol version on
# every subsequent HTTP request; servers that enforce it return 400 when it is
# absent. The header is a Streamable-HTTP-era construct — it is absent from the
# 2025-03-26 spec and from the 2024-11-05 legacy SSE transport — so it is
# injected on the Streamable HTTP path (``run``) only. A cheap regex pre-check
# gates the slow json.loads, mirroring ``_CANCELLED_METHOD_RE``.
_INITIALIZE_METHOD_RE = re.compile(r'"method"\s*:\s*"initialize"')


def _looks_like_initialize(line: str) -> bool:
    """Return True if ``line`` looks like a JSON-RPC ``initialize`` request.

    A cheap pre-filter so the relay only attempts to capture the negotiated
    protocol version from initialize responses. The trailing quote in the
    pattern means ``notifications/initialized`` does not match.
    """
    return bool(_INITIALIZE_METHOD_RE.search(line))


def _extract_protocol_version(payload: str) -> str | None:
    """Return ``result.protocolVersion`` from an InitializeResult, else None.

    Accepts the JSON-RPC response payload (the text after ``data: `` for an
    SSE-framed response, or the whole JSON body otherwise). Returns None for
    anything that is not an object carrying a string ``result.protocolVersion``.
    """
    try:
        msg = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(msg, dict):
        return None
    result = msg.get("result")
    if not isinstance(result, dict):
        return None
    pv = result.get("protocolVersion")
    return pv if isinstance(pv, str) else None


# Cancel-aware response filter (MCP cancellation spec SHOULDs).
#
# The MCP cancellation utility mandates two reciprocal SHOULDs:
# - a *receiver* must not send a response for a cancelled request;
# - a *canceller* must ignore any late response for a cancelled request.
# Both are violated in the wild (cf. anthropics/claude-code#51073 for the
# canceller side; modelcontextprotocol/python-sdk#2480 for the receiver
# side). As a stdin-to-HTTP middleman, mcp-stdio can enforce the receiver
# SHOULD on the wire by dropping any upstream response whose id has been
# cancelled by the client — see _CancelTracker and _emit below.
_CANCEL_TTL_SECS = 60.0
_CANCEL_GC_THRESHOLD = 256
_CANCELLED_METHOD_RE = re.compile(r'"method"\s*:\s*"notifications/cancelled"')


class _CancelTracker:
    """Thread-safe id→timestamp map of cancelled in-flight request ids.

    Callers on the stdin side push ids with ``add(id)`` when they see a
    ``notifications/cancelled``; the response-emit path queries with
    ``consume(id)`` and drops a matching response. ``consume`` removes the
    entry on the first match, so a cancelled id's late response is dropped
    exactly once — a later request that legitimately *reuses* the same id
    (permitted by JSON-RPC once the prior call is done) is then forwarded
    normally instead of being dropped for the whole TTL window. Entries
    expire after ``ttl`` seconds (monotonic clock — immune to NTP jumps),
    and the internal map is opportunistically garbage-collected when it
    grows past ``_CANCEL_GC_THRESHOLD`` entries so an adversarial peer cannot
    leak memory. Both transports share one instance; the SSE reader thread
    in ``run_sse`` reads concurrently with the main loop, hence the lock.
    """

    __slots__ = ("_seen", "_lock", "_ttl", "_now")

    def __init__(
        self,
        ttl: float = _CANCEL_TTL_SECS,
        now: Any = time.monotonic,
    ) -> None:
        self._seen: dict[Any, float] = {}
        self._lock = threading.Lock()
        self._ttl = ttl
        self._now = now

    def add(self, req_id: Any) -> None:
        if req_id is None:
            return
        with self._lock:
            self._seen[req_id] = self._now()
            if len(self._seen) > _CANCEL_GC_THRESHOLD:
                self._gc_locked()

    def contains(self, req_id: Any) -> bool:
        if req_id is None:
            return False
        with self._lock:
            ts = self._seen.get(req_id)
            if ts is None:
                return False
            if self._now() - ts > self._ttl:
                del self._seen[req_id]
                return False
            return True

    def consume(self, req_id: Any) -> bool:
        """Return True for a still-live cancelled id, removing it on match.

        Consuming on the first match bounds the drop to a single response per
        cancelled id, so a request that reuses the id within the TTL is not
        collateral-dropped. An expired entry is also removed and returns False.
        """
        if req_id is None:
            return False
        with self._lock:
            ts = self._seen.pop(req_id, None)
            if ts is None:
                return False
            return self._now() - ts <= self._ttl

    def discard(self, req_id: Any) -> None:
        """Untrack an id when the client forwards a fresh request reusing it.

        A new request with a previously-cancelled id supersedes the cancel
        (JSON-RPC permits id reuse once the prior call is done), so its response
        must be delivered rather than dropped as a "late cancelled response".
        """
        if req_id is None:
            return
        with self._lock:
            self._seen.pop(req_id, None)

    def _gc_locked(self) -> None:
        cutoff = self._now() - self._ttl
        expired = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in expired:
            del self._seen[k]


def _extract_cancel_id(line: str) -> Any:
    """Return ``params.requestId`` if ``line`` is a ``notifications/cancelled``.

    Uses a cheap regex pre-check to avoid a full ``json.loads`` on every
    stdin line — only cancellation notifications go through the slow
    path. Returns ``None`` if the line is not a cancellation (malformed
    JSON, wrong method, missing params, or missing requestId).

    Only a single (non-batch) ``notifications/cancelled`` is tracked: a
    cancellation buried inside a JSON-RPC batch array is intentionally not
    extracted, consistent with the cancel filter passing batches through
    untouched (the filter's narrow scope mirrors exactly what the spec
    covers, and batch responses are forwarded verbatim).
    """
    if not _CANCELLED_METHOD_RE.search(line):
        return None
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(msg, dict) or msg.get("method") != "notifications/cancelled":
        return None
    params = msg.get("params")
    if not isinstance(params, dict):
        return None
    return params.get("requestId")


def _error_response(message: str, req_id: Any = None) -> str:
    """Build a JSON-RPC error response."""
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": message},
            "id": req_id,
        }
    )


def _parse_retry_after(value: str | None) -> float | None:
    """Parse an HTTP ``Retry-After`` header value.

    Per RFC 7231 §7.1.3, ``Retry-After`` is either a non-negative integer
    number of seconds (delta-seconds) or an HTTP-date. Returns the number
    of seconds to wait, or ``None`` if the header is absent or
    unparseable. A past HTTP-date returns ``0`` (retry immediately).
    """
    if not value:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    # delta-seconds is the common case; try it first.
    try:
        secs = float(stripped)
    except ValueError:
        pass
    else:
        if math.isnan(secs) or math.isinf(secs):
            return None
        return max(0.0, secs)
    # Fall back to HTTP-date (RFC 7231 §7.1.1.1 — IMF-fixdate, obsolete
    # RFC 850, or ANSI C's asctime()).
    try:
        dt = email.utils.parsedate_to_datetime(stripped)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = (dt - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, delta)


def _handle_rate_limit(
    resp_headers: Any,
    attempt: int,
) -> float | None:
    """Decide how long to sleep for a 429 before retrying.

    Returns the seconds to sleep if a retry should be attempted, or
    ``None`` if the caller should give up (wait exceeds the cap, or this
    was the last allowed attempt — caller must then surface the 429).

    ``resp_headers`` accepts anything with ``.get("retry-after")``.
    ``attempt`` is the 1-based retry counter shared with the surrounding
    retry loop.
    """
    if attempt >= MAX_RETRIES:
        return None
    retry_after = _parse_retry_after(
        resp_headers.get("retry-after") if hasattr(resp_headers, "get") else None
    )
    if retry_after is None:
        # No hint from the server: reuse the transient-error backoff so
        # retry timing stays predictable across failure modes.
        return float(RETRY_DELAY * attempt)
    if retry_after > _RATE_LIMIT_SLEEP_CAP_SECS:
        # Server is asking for longer than we're willing to block. Let
        # the 429 propagate so the client can decide what to do.
        return None
    return retry_after


def _escape_js_line_separators(line: str) -> str:
    """Escape raw U+2028 / U+2029 to their JSON ``\\uXXXX`` form.

    Both are legal *unescaped* inside JSON strings but are JavaScript line
    terminators; some clients treat them as line breaks and hang or
    mis-frame the response (cf. modelcontextprotocol/typescript-sdk#2155).
    Escaping is lossless — the escaped form decodes to the identical
    character — so it is applied unconditionally, mirroring the
    no-flag, lossless ``_enforce_lf_stdio`` normalization. The cheap
    ``in`` pre-check keeps the common case allocation-free.

    Only upstream pass-through content reaches this path with raw
    separators: mcp-stdio's own responses go through ``json.dumps``
    (``ensure_ascii=True``), which already escapes them.
    """
    if "\u2028" in line or "\u2029" in line:
        return line.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return line


def _emit(line: str, tracker: "_CancelTracker | None") -> None:
    """Write one JSON-RPC line to stdout, filtering cancelled-id responses.

    Raw U+2028 / U+2029 are escaped first (``_escape_js_line_separators``)
    so a client that treats them as line terminators cannot mis-frame the
    output. The cancel filter then runs: when ``tracker`` is ``None``
    (feature disabled) the line is written unconditionally; otherwise the
    line is parsed and only proper JSON-RPC *responses* (objects with an id
    and either ``result`` or ``error``) are eligible for dropping.
    Notifications, server-initiated requests, JSON-RPC batches, and
    anything that fails to parse pass through — the filter is narrowly
    scoped to the case the spec covers.

    mcp-stdio's own synthesized error responses (``_error_response``)
    intentionally bypass this gate and call ``_write_line`` directly, so a
    cancel arriving mid-retry never leaves the client hanging without
    an answer for the line it just sent.
    """
    line = _escape_js_line_separators(line)
    if tracker is None:
        _write_line(line)
        return
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        _write_line(line)
        return
    if not isinstance(msg, dict):
        _write_line(line)
        return
    rid = msg.get("id")
    if rid is not None and ("result" in msg or "error" in msg):
        if tracker.consume(rid):
            log(f"dropped late response for cancelled id {rid!r}")
            return
    _write_line(line)


class _StreamResult:
    """Result of a streaming request."""

    __slots__ = ("session_id", "status_code", "www_authenticate", "protocol_version")

    def __init__(
        self,
        session_id: str | None,
        status_code: int,
        www_authenticate: str | None = None,
        protocol_version: str | None = None,
    ):
        self.session_id = session_id
        self.status_code = status_code
        self.www_authenticate = www_authenticate
        # Negotiated MCP protocol version captured from an InitializeResult
        # (only populated when the caller requests capture). See run().
        self.protocol_version = protocol_version


_INSUFFICIENT_SCOPE_RE = re.compile(r'error\s*=\s*"?insufficient_scope"?')
_SCOPE_QUOTED_RE = re.compile(r'scope\s*=\s*"([^"]*)"')
_SCOPE_UNQUOTED_RE = re.compile(r'scope\s*=\s*([^,\s]+)')


def _parse_www_authenticate_scope(header: str | None) -> str | None:
    """Extract the required scope from a Bearer insufficient_scope challenge.

    Returns the scope string when the challenge signals
    ``error="insufficient_scope"`` and carries a ``scope`` parameter;
    otherwise returns ``None``. Handles both quoted and unquoted
    parameter values per RFC 7235.

    Used to drive RFC 9470 / MCP step-up authorization (cf.
    anthropics/claude-code#44652).
    """
    if not header:
        return None
    if not _INSUFFICIENT_SCOPE_RE.search(header):
        return None
    match = _SCOPE_QUOTED_RE.search(header)
    if match:
        return match.group(1).strip()
    match = _SCOPE_UNQUOTED_RE.search(header)
    if match:
        return match.group(1).strip()
    return None


# WHATWG Server-Sent Events recognises only CR, LF, and CRLF as line
# terminators. Python's ``str.splitlines()`` and httpx's ``iter_lines`` split on
# a much larger set (``\n \r \x0b \x0c \x1c \x1d \x1e \x85 U+2028 U+2029``), but
# U+2028 / U+2029 / U+0085 are legal *unescaped* inside JSON strings (RFC 8259).
# Splitting an SSE ``data:`` payload on one of them tears the JSON-RPC message in
# half — the first fragment is emitted truncated and the continuation is dropped
# as an unknown field. This is the inbound mirror of the outbound hazard
# ``_escape_js_line_separators`` already guards (typescript-sdk#2155), so the SSE
# decoders below split on CR/LF/CRLF only.
_SSE_LINE_SPLIT_RE = re.compile(r"\r\n|\r|\n")


def _split_sse_text(text: str) -> list[str]:
    """Split a fully-buffered SSE body into lines on CR / LF / CRLF only."""
    return _SSE_LINE_SPLIT_RE.split(text)


def _iter_sse_lines(chunks: Iterable[str]) -> Iterator[str]:
    """Yield SSE lines from a text-chunk stream, splitting on CR/LF/CRLF only.

    Buffers across chunk boundaries so a ``\\r\\n`` straddling two chunks counts
    as a single terminator (a trailing ``\\r`` is held back until the next chunk
    resolves whether it is a lone CR or the first half of a CRLF). The final
    unterminated remainder is yielded last. Used for the streaming SSE paths,
    where httpx's ``iter_lines`` would over-split (see ``_SSE_LINE_SPLIT_RE``).
    """
    buf = ""
    for chunk in chunks:
        if not chunk:
            continue
        buf += chunk
        hold = ""
        if buf.endswith("\r"):
            # A trailing CR may be the first half of a CRLF whose LF is in the
            # next chunk; hold it so the pair is not split into two lines.
            hold = "\r"
            buf = buf[:-1]
        parts = _SSE_LINE_SPLIT_RE.split(buf)
        buf = parts.pop() + hold
        for line in parts:
            yield line
    if buf.endswith("\r"):
        # A held CR at end of input is itself a terminator.
        buf = buf[:-1]
    if buf:
        yield buf


def _iter_sse_events(lines: Iterable[str]) -> Iterator[tuple[str, str]]:
    """Yield ``(event_type, data)`` pairs from SSE lines per the WHATWG spec.

    Implements the WHATWG Server-Sent Events line-decoding algorithm so every
    SSE-decoding site parses identically:

    - a ``data:`` field strips at most one leading U+0020 from its value, so a
      space-less ``data:{...}`` is valid (servers are not required to emit the
      conventional ``data: {...}`` with a space);
    - ``event:`` sets the event type, which defaults to ``"message"`` and resets
      after every dispatched event;
    - ``:``-prefixed comment lines and unrecognised fields are ignored;
    - the ``id:`` and ``retry:`` fields are intentionally ignored: mcp-stdio
      does not implement SSE resumption (no ``Last-Event-ID`` replay on
      reconnect) or server-driven reconnect timing for the legacy GET stream;
    - an event is dispatched on each blank-line boundary with its ``data:``
      fields concatenated by LF;
    - a final unterminated event with non-empty data is also dispatched at end
      of input, so a response body that omits the trailing blank line is not
      silently dropped.

    Callers decide which event types to act on (``message`` for JSON-RPC
    payloads, ``endpoint`` for the legacy SSE bootstrap).
    """
    event_type = "message"
    data_lines: list[str] = []
    for line in lines:
        if line == "":
            if data_lines:
                yield event_type, "\n".join(data_lines)
            event_type = "message"
            data_lines = []
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "event":
            event_type = value
        elif field == "data":
            data_lines.append(value)
    if data_lines:
        yield event_type, "\n".join(data_lines)


def _post_and_stream(
    client: httpx.Client,
    url: str,
    content: str,
    headers: dict[str, str],
    req_id: Any,
    tracker: _CancelTracker | None = None,
    *,
    capture_init: bool = False,
) -> _StreamResult | None:
    """Send a POST and stream the response to stdout with retry.

    Handles both SSE and JSON responses.  Returns a ``_StreamResult``
    on success (including non-200 status for caller to handle), or
    ``None`` when all retries are exhausted (error already printed).

    When ``capture_init`` is set the streamed payload is additionally
    parsed for ``result.protocolVersion`` (the negotiated MCP protocol
    version from an InitializeResult), surfaced via
    ``_StreamResult.protocol_version``. Parsing is read-only and never
    affects what is written to stdout.
    """
    last_error: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        # Tracks whether any payload has been committed to stdout on this
        # attempt. Once a byte is written to the client the non-idempotent
        # POST can no longer be safely replayed, so a mid-stream transient
        # error must surface an error instead of retrying — otherwise the
        # server re-streams and the client sees duplicate JSON-RPC responses
        # (and tools/call may execute twice server-side).
        emitted = False
        try:
            with client.stream("POST", url, content=content, headers=headers) as resp:
                session = resp.headers.get("mcp-session-id")
                www_auth = resp.headers.get("www-authenticate")

                if resp.status_code == 429:
                    resp.read()
                    sleep_secs = _handle_rate_limit(resp.headers, attempt)
                    if sleep_secs is None:
                        return _StreamResult(session, 429, www_auth)
                    log(
                        f"attempt {attempt}/{MAX_RETRIES} got HTTP 429, "
                        f"sleeping {sleep_secs:.1f}s before retry"
                    )
                    time.sleep(sleep_secs)
                    continue

                if resp.status_code != 200:
                    resp.read()
                    return _StreamResult(session, resp.status_code, www_auth)

                pv: str | None = None
                content_type = resp.headers.get("content-type", "")
                if "text/event-stream" in content_type:
                    for event_type, payload in _iter_sse_events(_iter_sse_lines(resp.iter_text())):
                        if event_type != "message":
                            continue
                        if capture_init and pv is None:
                            pv = _extract_protocol_version(payload)
                        _emit(payload, tracker)
                        emitted = True
                else:
                    resp.read()
                    text = resp.text.strip()
                    if text:
                        if capture_init:
                            pv = _extract_protocol_version(text)
                        _emit(text, tracker)
                        emitted = True

                return _StreamResult(session, 200, protocol_version=pv)
        except httpx.TransportError as e:
            # TransportError is the supertype of every transient network/timeout/
            # protocol failure: ConnectError/ReadError/Write*, ConnectTimeout/
            # ReadTimeout/PoolTimeout, and RemoteProtocolError (mid-response
            # server disconnect — common during half-open recovery). Catching
            # the narrow leaf list missed several of these and let them crash the
            # whole gateway. Non-transport (programming) errors still propagate.
            last_error = e
            log(f"attempt {attempt}/{MAX_RETRIES} failed: {e}")
            if emitted:
                # Response already partially delivered to the client; replaying
                # the POST would duplicate it. Surface a stream-interrupted
                # error (at-most-once) rather than retry.
                log("upstream stream interrupted after partial delivery; not retrying")
                _write_line(
                    _error_response(f"upstream stream interrupted: {e}", req_id)
                )
                return None
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)

    log(f"request failed after retries: {last_error}")
    _write_line(_error_response(str(last_error), req_id))
    return None


def _post_parsed(
    client: httpx.Client,
    url: str,
    content: str,
    headers: dict[str, str],
    req_id: Any,
) -> tuple[dict[str, Any] | None, _StreamResult | None]:
    """Send a POST and return the parsed JSON-RPC response.

    Mirrors the retry behaviour of ``_post_and_stream`` but buffers the
    response so that callers can inspect the JSON before writing anything
    to stdout. Used by the pagination helper, which needs to inspect
    ``result.nextCursor`` across multiple requests.

    Returns a tuple of ``(parsed, stream_result)``. ``parsed`` is the
    decoded response dict on success, or ``None`` on non-200 / parse
    failure. ``stream_result`` is ``None`` only when all retries are
    exhausted (and the error was already printed to stdout).
    """
    last_error: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = client.post(url, content=content, headers=headers)
            session = resp.headers.get("mcp-session-id")
            www_auth = resp.headers.get("www-authenticate")
            if resp.status_code == 429:
                sleep_secs = _handle_rate_limit(resp.headers, attempt)
                if sleep_secs is None:
                    return None, _StreamResult(session, 429, www_auth)
                log(
                    f"attempt {attempt}/{MAX_RETRIES} got HTTP 429, "
                    f"sleeping {sleep_secs:.1f}s before retry"
                )
                time.sleep(sleep_secs)
                continue
            if resp.status_code != 200:
                return None, _StreamResult(session, resp.status_code, www_auth)

            content_type = resp.headers.get("content-type", "")
            if "text/event-stream" in content_type:
                for event_type, payload in _iter_sse_events(_split_sse_text(resp.text)):
                    if event_type != "message":
                        continue
                    try:
                        return json.loads(payload), _StreamResult(session, 200)
                    except json.JSONDecodeError:
                        continue
                return None, _StreamResult(session, 200)

            text = resp.text.strip()
            if not text:
                return None, _StreamResult(session, 200)
            try:
                return json.loads(text), _StreamResult(session, 200)
            except json.JSONDecodeError:
                return None, _StreamResult(session, 200)
        except httpx.TransportError as e:
            # TransportError is the supertype of every transient network/timeout/
            # protocol failure: ConnectError/ReadError/Write*, ConnectTimeout/
            # ReadTimeout/PoolTimeout, and RemoteProtocolError (mid-response
            # server disconnect — common during half-open recovery). Catching
            # the narrow leaf list missed several of these and let them crash the
            # whole gateway. Non-transport (programming) errors still propagate.
            last_error = e
            log(f"attempt {attempt}/{MAX_RETRIES} failed: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)

    log(f"request failed after retries: {last_error}")
    _write_line(_error_response(str(last_error), req_id))
    return None, None


# tools/call requests that serialize an empty argument map as ``null``.
# Some clients (Go/Java/C# serializers) emit ``"arguments": null``; strict
# MCP servers validate ``arguments`` as an optional object and reject the
# null form with -32603 (cf. modelcontextprotocol/typescript-sdk#2012). The
# regex is a cheap gate before the json round-trip; the parsed-structure
# check below is authoritative.
_NULL_ARGUMENTS_RE = re.compile(r'"arguments"\s*:\s*null')


def _normalize_null_arguments(line: str) -> str:
    """Rewrite a ``tools/call`` request's null ``arguments`` to ``{}``.

    ``{}`` is accepted by both optional- and required-object servers, so it
    is the safe normalization of the "no arguments" intent. Narrowly
    scoped: only a ``tools/call`` whose ``params.arguments`` key is present
    and ``null`` is rewritten — a string value that merely contains the
    literal ``"arguments":null`` is left untouched (the parsed-structure
    check, not the regex, decides). JSON-RPC batch arrays and other methods
    (e.g. ``prompts/get``, a deliberate non-goal) pass through unchanged.
    """
    if not _NULL_ARGUMENTS_RE.search(line):
        return line
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return line
    if not isinstance(msg, dict) or msg.get("method") != "tools/call":
        return line
    params = msg.get("params")
    if isinstance(params, dict) and "arguments" in params and params["arguments"] is None:
        params["arguments"] = {}
        return json.dumps(msg)
    return line


def _detect_paginated_list(line: str) -> tuple[str, str] | None:
    """Return ``(method, result_key)`` if the request should auto-paginate.

    A request auto-paginates when the method is one of the spec's
    paginated list endpoints and the client did not supply ``cursor``.
    If the client already supplies ``cursor`` we pass through: they are
    driving pagination themselves and should receive the raw response.
    """
    try:
        request = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(request, dict):
        return None
    method = request.get("method")
    if method not in PAGINATED_LIST_METHODS:
        return None
    params = request.get("params")
    if isinstance(params, dict) and "cursor" in params:
        return None
    return method, PAGINATED_LIST_METHODS[method]


def _paginate_and_stream(
    client: httpx.Client,
    url: str,
    line: str,
    headers: dict[str, str],
    req_id: Any,
    result_key: str,
    tracker: _CancelTracker | None = None,
) -> _StreamResult | None:
    """Transparently follow ``result.nextCursor`` and emit one merged response.

    Issues up to ``MAX_LIST_PAGES`` POSTs, threading each response's
    ``nextCursor`` into the next request's ``params.cursor``. The final
    response written to stdout contains the concatenated list items and
    no ``nextCursor``.

    Non-200 on page 1 is propagated to the caller so the outer loop can
    handle 401 / 404 recovery just like a non-paginated request. Errors
    on page 2+ return the accumulated partial result rather than losing
    items already collected.
    """
    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        return _post_and_stream(client, url, line, headers, req_id, tracker)

    base_params = request.get("params")
    params: dict[str, Any] = dict(base_params) if isinstance(base_params, dict) else {}
    merged_result: dict[str, Any] | None = None
    last_session: str | None = None
    truncated = False

    for page in range(1, MAX_LIST_PAGES + 1):
        page_request = dict(request)
        page_request["params"] = params
        page_content = json.dumps(page_request)

        parsed, stream = _post_parsed(client, url, page_content, headers, req_id)
        if stream is None:
            if page == 1:
                return None  # error already printed
            log(
                f"pagination: page {page} exhausted retries, "
                f"returning partial result"
            )
            break

        if stream.session_id:
            last_session = stream.session_id

        if stream.status_code != 200:
            if page == 1:
                return stream  # let outer 401/404 recovery run
            log(
                f"pagination: page {page} returned HTTP {stream.status_code}, "
                f"returning partial result"
            )
            break

        if parsed is None:
            if page == 1:
                return _post_and_stream(client, url, line, headers, req_id, tracker)
            log(
                f"pagination: page {page} response not parseable, "
                f"returning partial result"
            )
            break

        page_result = parsed.get("result")
        if not isinstance(page_result, dict):
            # Error response or unexpected shape — forward as-is from page 1,
            # otherwise stop and flush what we have.
            if page == 1:
                _emit(json.dumps(parsed), tracker)
                return stream
            break

        if merged_result is None:
            merged_result = {k: v for k, v in page_result.items() if k != "nextCursor"}
            if not isinstance(merged_result.get(result_key), list):
                merged_result[result_key] = []
        else:
            items = page_result.get(result_key)
            if isinstance(items, list):
                merged_result[result_key].extend(items)

        next_cursor = page_result.get("nextCursor")
        if not next_cursor:
            break
        params["cursor"] = next_cursor
    else:
        truncated = True
        log(
            f"pagination: reached MAX_LIST_PAGES={MAX_LIST_PAGES}, "
            f"truncating results"
        )

    if merged_result is None:
        merged_result = {result_key: []}

    merged_response: dict[str, Any] = {
        "jsonrpc": request.get("jsonrpc", "2.0"),
        "id": request.get("id"),
        "result": merged_result,
    }
    _emit(json.dumps(merged_response), tracker)
    _ = truncated  # kept for future _meta annotation
    return _StreamResult(last_session, 200)


def _reinitialize(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    protocol_version: str | None = None,
) -> tuple[str | None, str | None]:
    """Send an initialize handshake to establish a new MCP session.

    Used to recover after a session expires (server returns 404 on the
    next request). Performs the full MCP initialize handshake:

    1. POST an ``initialize`` request to get a new session ID
    2. POST a ``notifications/initialized`` notification to signal
       readiness (required by the MCP spec before any other requests)

    The re-handshake may renegotiate a different protocol version than the
    one originally captured (e.g. a downgrade), so the InitializeResult is
    parsed for ``result.protocolVersion`` and the freshly negotiated value is
    used for the ``notifications/initialized`` header and returned to the
    caller. ``notifications/initialized`` is the first "subsequent request"
    of the recovered session, so it carries ``MCP-Protocol-Version``; the
    initialize POST itself omits it — it is the (re)negotiation and predates
    a known version.

    Returns ``(new_session_id, negotiated_protocol_version)``. The session id
    is ``None`` on failure; the protocol version falls back to the passed-in
    ``protocol_version`` when the response omits ``result.protocolVersion``.
    """
    initialize_msg = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 0,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-stdio", "version": __version__},
            },
        }
    )
    try:
        resp = client.post(url, content=initialize_msg, headers=headers)
    except httpx.HTTPError as e:
        log(f"re-initialize request failed: {e}")
        return None, protocol_version
    if resp.status_code != 200:
        log(f"re-initialize returned HTTP {resp.status_code}")
        return None, protocol_version
    new_session_id = resp.headers.get("mcp-session-id")
    if not new_session_id:
        log("re-initialize response missing mcp-session-id header")
        return None, protocol_version

    # Re-capture the negotiated protocol version from the InitializeResult so
    # the recovered session's header matches the version actually in force.
    negotiated = protocol_version
    if "text/event-stream" in resp.headers.get("content-type", ""):
        for event_type, payload in _iter_sse_events(_split_sse_text(resp.text)):
            if event_type == "message":
                pv = _extract_protocol_version(payload)
                if pv:
                    negotiated = pv
                    break
    else:
        pv = _extract_protocol_version(resp.text.strip())
        if pv:
            negotiated = pv

    # MCP spec: send notifications/initialized before any other requests
    initialized_msg = json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    initialized_headers = dict(headers)
    initialized_headers["Mcp-Session-Id"] = new_session_id
    if negotiated:
        initialized_headers["MCP-Protocol-Version"] = negotiated
    try:
        resp = client.post(url, content=initialized_msg, headers=initialized_headers)
    except httpx.HTTPError as e:
        log(f"notifications/initialized failed: {e}")
        return None, protocol_version
    if resp.status_code not in (200, 202):
        log(f"notifications/initialized returned HTTP {resp.status_code}")
        return None, protocol_version
    return new_session_id, negotiated


def check_connection(
    url: str,
    headers: dict[str, str],
    *,
    timeout_connect: float = 10,
    timeout_read: float = 120,
) -> bool:
    """Check MCP server connectivity by sending an initialize request.

    Returns True if the server responds successfully.
    """
    initialize_msg = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1,
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-stdio", "version": __version__},
            },
        }
    )

    client = httpx.Client(
        timeout=httpx.Timeout(connect=timeout_connect, read=timeout_read, write=30, pool=10)
    )

    try:
        log(f"testing connection to {url}")
        resp = client.post(url, content=initialize_msg, headers=headers)

        if resp.status_code != 200:
            # Do not surface the response body — server error responses
            # commonly carry session IDs, stack traces, or echoed request
            # data. The status code alone is the right operational signal
            # for the --check probe. See #16.
            log(f"✗ HTTP {resp.status_code}")
            return False

        log(f"✓ Connected (HTTP {resp.status_code})")

        # Parse initialize response from JSON or SSE
        content_type = resp.headers.get("content-type", "")
        result_data: dict[str, Any] | None = None

        if "text/event-stream" in content_type:
            for event_type, payload in _iter_sse_events(_split_sse_text(resp.text)):
                if event_type != "message":
                    continue
                try:
                    result_data = json.loads(payload)
                    break
                except json.JSONDecodeError:
                    continue
        else:
            try:
                result_data = json.loads(resp.text)
            except json.JSONDecodeError:
                pass

        if result_data and "result" in result_data:
            result = result_data["result"]
            server_info = result.get("serverInfo", {})
            name = server_info.get("name", "unknown")
            version = server_info.get("version", "?")
            protocol = result.get("protocolVersion", "?")
            log(f"✓ MCP initialize: server={name} v{version}, protocol={protocol}")

            caps = result.get("capabilities", {})
            tools = "yes" if caps.get("tools") else "no"
            resources = "yes" if caps.get("resources") else "no"
            prompts = "yes" if caps.get("prompts") else "no"
            log(f"✓ Capabilities: tools={tools}, resources={resources}, prompts={prompts}")
        elif result_data and "error" in result_data:
            err = result_data["error"]
            log(f"✗ MCP error: {err.get('message', err)}")
            return False
        else:
            log("✓ Server responded (could not parse initialize result)")

        if "mcp-session-id" in resp.headers:
            log(f"✓ Session ID: {resp.headers['mcp-session-id']}")

        return True
    except Exception as e:
        log(f"✗ Connection failed: {e}")
        return False
    finally:
        client.close()


def run(
    url: str,
    headers: dict[str, str],
    *,
    timeout_connect: float = 10,
    timeout_read: float = 120,
    timeout_write: float = 30,
    tcp_keepalive: bool = True,
    cancel_filter: bool = True,
    normalize_arguments: bool = True,
    token_refresher: Any = None,
    scope_upgrader: Any = None,
) -> None:
    """Run the stdio-to-HTTP relay loop.

    Reads JSON-RPC messages from stdin, sends them as HTTP POST to the
    remote MCP server, and writes responses to stdout.

    Args:
        url: Remote MCP server URL
        headers: HTTP headers to send with each request
        timeout_connect: Connection timeout in seconds
        timeout_read: Read timeout in seconds
        timeout_write: Write timeout in seconds
        tcp_keepalive: When True (default), enable TCP keepalive on the
            underlying socket to detect half-open connections at the
            network layer. See ``_tcp_keepalive_socket_options`` for
            platform-specific tuning (#9).
        cancel_filter: When True (default), track ids from
            ``notifications/cancelled`` seen on stdin and drop any late
            upstream JSON-RPC response carrying one of those ids before
            it reaches stdout. Enforces the MCP cancellation spec's
            receiver-side SHOULD on behalf of non-compliant servers and
            shields the downstream client from canceller-side bugs such
            as anthropics/claude-code#51073. Disable (``False``) only
            when debugging raw upstream traffic.
        normalize_arguments: When True (default), rewrite a ``tools/call``
            request whose ``params.arguments`` is ``null`` to ``{}`` before
            forwarding, so strict servers that reject the null form
            (modelcontextprotocol/typescript-sdk#2012) accept the call.
            Disable (``False``) to forward the client request verbatim.
        token_refresher: Optional callable that returns updated headers
            on successful token refresh, or None on failure. Called when
            the server returns HTTP 401.
        scope_upgrader: Optional callable invoked when the server
            returns HTTP 403 with a ``Bearer error="insufficient_scope"``
            challenge. It receives the scope string from the challenge
            and returns updated headers containing a broader-scope
            token, or None on failure (RFC 9470 step-up authorization;
            cf. anthropics/claude-code#44652).
    """

    # Graceful shutdown on SIGTERM/SIGINT
    def _shutdown(signum: int, _: Any) -> None:
        log(f"received signal {signum}, shutting down")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log(f"connecting to {url}")

    session_id: str | None = None
    # Negotiated MCP protocol version, captured from the InitializeResult and
    # injected as MCP-Protocol-Version on every subsequent request (spec rev
    # 2025-06-18). Streamable HTTP only — see _looks_like_initialize.
    protocol_version: str | None = None
    tracker: _CancelTracker | None = _CancelTracker() if cancel_filter else None
    client = httpx.Client(
        transport=_make_httpx_transport(tcp_keepalive=tcp_keepalive),
        timeout=httpx.Timeout(
            connect=timeout_connect,
            read=timeout_read,
            write=timeout_write,
            pool=10,
        )
    )

    def _prepare_headers() -> dict[str, str]:
        """Build per-request headers with the current session + protocol version."""
        h = dict(headers)
        if session_id:
            h["Mcp-Session-Id"] = session_id
        if protocol_version:
            h["MCP-Protocol-Version"] = protocol_version
        return h

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            if normalize_arguments:
                line = _normalize_null_arguments(line)

            if tracker is not None:
                cid = _extract_cancel_id(line)
                if cid is not None:
                    tracker.add(cid)

            req_id = _extract_id(line)
            if tracker is not None and req_id is not None:
                # A request reusing a previously-cancelled id supersedes that
                # cancel — untrack it so its response is delivered, not dropped.
                tracker.discard(req_id)

            req_headers = _prepare_headers()

            def _dispatch(content: str, h: dict[str, str]) -> _StreamResult | None:
                nonlocal protocol_version
                detected = _detect_paginated_list(content)
                if detected:
                    # The pagination branch never captures protocol_version.
                    # That is correct because `initialize` is not in
                    # PAGINATED_LIST_METHODS, so an initialize request can never
                    # take this branch — keep that invariant if the table grows.
                    return _paginate_and_stream(
                        client, url, content, h, req_id, detected[1], tracker
                    )
                # Capture-once semantics: we only learn the version from the
                # first initialize. A later client-driven re-initialize that
                # renegotiates a different version is not picked up — rare, and
                # avoids re-parsing every response on the hot path.
                #
                # Response-only: the version comes from the server's
                # InitializeResult, not the client's requested version. If a
                # (non-compliant) server omits result.protocolVersion, no
                # header is sent rather than guessing — a server that both
                # omits it and enforces the header would be self-contradictory.
                capture_init = protocol_version is None and _looks_like_initialize(content)
                result = _post_and_stream(
                    client, url, content, h, req_id, tracker, capture_init=capture_init
                )
                if (
                    result is not None
                    and result.protocol_version
                    and protocol_version is None
                ):
                    protocol_version = result.protocol_version
                    log(f"negotiated MCP protocol version: {protocol_version}")
                return result

            result = _dispatch(line, req_headers)
            if result is None:
                # All retries exhausted — error already printed
                session_id = None
                continue

            # Adopt a server-supplied session id from THIS response before the
            # 401/403 recovery branches rebuild their retry headers, so a server
            # that rotates/assigns Mcp-Session-Id alongside an auth challenge is
            # honoured on the retry rather than re-sending the stale one. (The
            # 404 branch re-establishes its own fresh session below.)
            if result.session_id:
                session_id = result.session_id

            # Recovery is single-pass and ordered auth-before-session: the three
            # branches below are sequential `if`s (not `elif`), each firing at
            # most once per stdin line. A 401/403 whose retry returns 404 still
            # flows into the 404 branch and recovers; the converse does NOT — a
            # 404 retry that comes back 401/403 (token expired during the reinit
            # window), or a 401/403 retry that fails the same way again, is not
            # re-recovered and surfaces as a JSON-RPC error (never a hang, #11).
            # The downstream client retries at its own level. This bounded
            # single attempt is deliberate: it avoids unbounded recovery loops.

            # Token expired (401) — refresh and retry once
            if result.status_code == 401 and token_refresher:
                log("received 401, attempting token refresh")
                new_headers = token_refresher()
                if new_headers:
                    headers.update(new_headers)
                    req_headers = _prepare_headers()
                    result = _dispatch(line, req_headers)
                    if result is None:
                        # Retries exhausted ⇒ the session may be stale too;
                        # reset for symmetry with the top-level None handling.
                        session_id = None
                        continue
                else:
                    log("token refresh failed, returning error")
                    _write_line(_error_response("authentication failed", req_id))
                    continue

            # Insufficient scope (403) — step-up authorization and retry once
            if result.status_code == 403 and scope_upgrader:
                required_scope = _parse_www_authenticate_scope(
                    result.www_authenticate
                )
                if required_scope is not None:
                    log(
                        f"received 403 insufficient_scope "
                        f"(required: {required_scope}), attempting step-up"
                    )
                    new_headers = scope_upgrader(required_scope)
                    if new_headers:
                        headers.update(new_headers)
                        req_headers = _prepare_headers()
                        result = _dispatch(line, req_headers)
                        if result is None:
                            # Retries exhausted ⇒ assume the session is stale,
                            # for symmetry with the top-level None handling.
                            session_id = None
                            continue
                    else:
                        log("step-up authorization failed, returning error")
                        _write_line(_error_response("authorization failed", req_id))
                        continue

            # Session expired (404) — reset, re-initialize, then retry
            if result.status_code == 404 and session_id:
                log("session expired, re-initializing and retrying")
                session_id = None
                new_session_id, renegotiated = _reinitialize(
                    client, url, dict(headers), protocol_version
                )
                if new_session_id is None:
                    log("re-initialize failed, dropping request")
                    _write_line(_error_response("session lost", req_id))
                    continue
                session_id = new_session_id
                # Track the re-negotiated version so the MCP-Protocol-Version
                # header on the retried request matches the recovered session.
                if renegotiated and renegotiated != protocol_version:
                    log(f"re-negotiated MCP protocol version: {renegotiated}")
                    protocol_version = renegotiated
                req_headers = _prepare_headers()
                result = _dispatch(line, req_headers)
                if result is None:
                    continue

            if result.session_id:
                session_id = result.session_id

            # Fall-through error for any unhandled 4xx/5xx so the MCP client
            # never hangs waiting for a response. 200 bodies were already
            # streamed by _post_and_stream; 202 is reserved for notifications
            # and intentionally produces no stdout. See #11.
            if result.status_code >= 400:
                log(f"upstream returned HTTP {result.status_code}")
                _write_line(_error_response(f"HTTP {result.status_code}", req_id))
    finally:
        client.close()


class _SseState:
    """Shared state between SSE reader thread and main stdin loop.

    ``endpoint_url`` is written by the reader thread (set on the ``endpoint``
    event, cleared to ``None`` on stream end / disconnect) and read by the main
    loop. It is deliberately a plain single-word attribute relied upon to be
    atomically published under the CPython GIL — no lock — because the only
    consumer re-checks it after a local capture and emits "SSE endpoint
    unavailable" if it raced to ``None``. A stale-after-reconnect read is
    acceptable in practice: legacy SSE reconnect endpoints are stable. ``ready``
    / ``stop`` are ``threading.Event``s, which carry their own synchronization.
    """

    __slots__ = ("endpoint_url", "ready", "stop")

    def __init__(self) -> None:
        self.endpoint_url: str | None = None
        self.ready = threading.Event()
        self.stop = threading.Event()


def _sse_reader_loop(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    state: _SseState,
    tracker: _CancelTracker | None = None,
    headers_lock: threading.Lock | None = None,
) -> None:
    """Reader thread: maintain SSE GET stream and dispatch events.

    Parses the SSE event stream per the WHATWG Server-Sent Events
    specification (via the shared ``_iter_sse_events`` decoder). The first
    ``endpoint`` event provides the POST URL (which may be relative —
    resolved with urljoin). Subsequent ``message`` events are JSON-RPC
    responses written to stdout.

    ``headers`` is shared with the main stdin loop, which may mutate it on a
    401/403 token refresh. ``headers_lock`` (when provided) serialises the
    per-reconnect snapshot taken here against those mutations so the request
    build never iterates a dict that is changing under it.

    Reconnects automatically on disconnect.
    """
    while not state.stop.is_set():
        try:
            if headers_lock is not None:
                with headers_lock:
                    req_headers = dict(headers)
            else:
                req_headers = dict(headers)
            with client.stream("GET", url, headers=req_headers) as resp:
                if resp.status_code != 200:
                    log(f"SSE connection failed: HTTP {resp.status_code}")
                    state.ready.set()
                    return

                for event_type, data in _iter_sse_events(_iter_sse_lines(resp.iter_text())):
                    if state.stop.is_set():
                        return
                    if event_type == "endpoint":
                        resolved = urljoin(url, data)
                        # The endpoint event may be a relative path (resolved
                        # against the GET url) or absolute. A compromised / MITM'd
                        # stream that injects an absolute cross-origin endpoint
                        # would otherwise redirect every authenticated POST — and
                        # its Authorization header — to a different origin. Refuse
                        # a cross-origin endpoint when credentials would be sent.
                        has_auth = any(k.lower() == "authorization" for k in req_headers)
                        if has_auth and not _same_origin(resolved, url):
                            log(
                                f"warning: refusing cross-origin SSE endpoint "
                                f"{resolved!r} (differs from {url!r}) — would leak "
                                f"credentials. Ignoring. See #13."
                            )
                            state.ready.set()  # unblock startup; endpoint stays None
                            continue
                        state.endpoint_url = resolved
                        state.ready.set()
                        log(f"SSE endpoint: {resolved}")
                    elif event_type == "message":
                        _emit(data, tracker)

                if state.stop.is_set():
                    return
                log("SSE stream ended, reconnecting")
                # Clear ``ready`` BEFORE nulling endpoint_url so the main loop's
                # ready.wait() blocks out the in-progress reconnect instead of
                # returning immediately on a stale set() and surfacing a spurious
                # "SSE endpoint unavailable".
                state.ready.clear()
                state.endpoint_url = None
                # Responsive reconnect delay: exits immediately on stop.
                if state.stop.wait(RETRY_DELAY):
                    return
        except httpx.HTTPError as e:
            if state.stop.is_set():
                return
            log(f"SSE disconnected, reconnecting: {e}")
            state.ready.clear()  # clear before nulling endpoint_url (see above)
            state.endpoint_url = None
            if state.stop.wait(RETRY_DELAY):
                return
        except Exception as e:  # noqa: BLE001 — thread safety net
            log(f"SSE reader unexpected error: {e}")
            state.ready.set()
            return


def run_sse(
    url: str,
    headers: dict[str, str],
    *,
    timeout_connect: float = 10,
    timeout_read: float = 120,
    timeout_write: float = 30,
    sse_read_timeout: float | None = 300,
    tcp_keepalive: bool = True,
    cancel_filter: bool = True,
    normalize_arguments: bool = True,
    token_refresher: Any = None,
    scope_upgrader: Any = None,
) -> None:
    """Run the stdio-to-SSE relay loop (MCP 2024-11-05 legacy transport).

    This implements the legacy SSE transport from the MCP 2024-11-05 spec:

    1. Open a persistent ``GET`` connection to the SSE endpoint
    2. Receive the first ``endpoint`` event containing the POST URL
    3. For each stdin line, POST the JSON-RPC message to that URL
    4. Receive responses via ``message`` events on the SSE stream

    Spec references:
    - WHATWG HTML — Server-Sent Events
      https://html.spec.whatwg.org/multipage/server-sent-events.html
    - MCP 2024-11-05 — HTTP with SSE Transport
      https://modelcontextprotocol.io/specification/2024-11-05/basic/transports

    Args:
        url: Remote MCP server SSE endpoint URL
        headers: HTTP headers to send with each request
        timeout_connect: Connection timeout in seconds
        timeout_read: Read timeout for the POST request
        timeout_write: Write timeout in seconds
        sse_read_timeout: Idle read timeout (seconds) on the long-lived
            SSE GET stream. A silent half-open TCP connection (dropped by
            a proxy, NAT, or firewall during a long-running tool call)
            will raise ``httpx.ReadTimeout`` after this interval and
            trigger an automatic reconnect instead of hanging forever.
            Set to ``None`` or ``0`` to opt out of the timeout and
            restore the previous unbounded-read behaviour. Defaults to
            300 seconds, matching the MCP Python SDK (#9).
        tcp_keepalive: When True (default), enable TCP keepalive at the
            socket layer in addition to ``sse_read_timeout``. Keepalive
            detects half-open TCP faster (≈120 s on Linux/macOS/BSD) and
            works regardless of whether the server sends SSE keepalive
            comments. See ``_tcp_keepalive_socket_options`` for the
            platform-specific tuning, and #9 for the upstream context.
        cancel_filter: When True (default), track ids from
            ``notifications/cancelled`` seen on stdin and drop any late
            upstream response carrying one of those ids on the SSE
            stream before it reaches stdout. See ``run`` for the full
            rationale.
        normalize_arguments: When True (default), rewrite a ``tools/call``
            request whose ``params.arguments`` is ``null`` to ``{}`` before
            forwarding. See ``run`` for the full rationale.
        token_refresher: Optional callable that returns updated headers
            on successful token refresh, or None on failure. Called when
            the server returns HTTP 401 on POST.
        scope_upgrader: Optional callable invoked when the server returns
            HTTP 403 with a ``Bearer error="insufficient_scope"``
            challenge on POST. Receives the scope string from the
            challenge and returns updated headers containing a
            broader-scope token, or None on failure. See #17.
    """

    def _shutdown(signum: int, _: Any) -> None:
        log(f"received signal {signum}, shutting down")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log(f"connecting to {url} (SSE transport)")

    # SSE GET is long-lived. Give it its own read timeout so a half-open
    # TCP connection (silent mid-tool-call) surfaces as a ReadTimeout
    # rather than a forever-hang; the reader loop then reconnects on
    # its own. Both ``None`` and ``0`` mean "disabled" — ``0`` is the CLI
    # escape hatch and ``None`` is the programmatic one. POST requests
    # use the separate timeout_read below.
    effective_sse_read = (
        None if sse_read_timeout in (None, 0) else sse_read_timeout
    )
    client = httpx.Client(
        transport=_make_httpx_transport(tcp_keepalive=tcp_keepalive),
        timeout=httpx.Timeout(
            connect=timeout_connect,
            read=effective_sse_read,
            write=timeout_write,
            pool=10,
        )
    )

    tracker: _CancelTracker | None = _CancelTracker() if cancel_filter else None
    state = _SseState()
    # The reader thread snapshots ``headers`` on every (re)connect while the
    # main loop below may mutate it on a 401/403 token refresh. Serialise the
    # two so the GET request build never iterates a dict mid-mutation.
    headers_lock = threading.Lock()
    reader = threading.Thread(
        target=_sse_reader_loop,
        args=(client, url, headers, state, tracker, headers_lock),
        daemon=True,
    )
    reader.start()

    if not state.ready.wait(timeout=timeout_connect):
        log("timed out waiting for SSE endpoint event")
        state.stop.set()
        client.close()
        sys.exit(1)

    if state.endpoint_url is None:
        log("SSE reader terminated before endpoint event")
        state.stop.set()
        client.close()
        sys.exit(1)

    def _snapshot_headers() -> dict[str, str]:
        """Take a consistent copy of ``headers`` under the lock for a POST.

        Symmetric with the reader thread's snapshot and the 401/403 mutations
        so every cross-thread access to ``headers`` is serialised — no POST
        ever iterates the dict while a refresh is updating it.
        """
        with headers_lock:
            return dict(headers)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            if normalize_arguments:
                line = _normalize_null_arguments(line)

            if tracker is not None:
                cid = _extract_cancel_id(line)
                if cid is not None:
                    tracker.add(cid)

            req_id = _extract_id(line)
            if tracker is not None and req_id is not None:
                # A request reusing a previously-cancelled id supersedes that
                # cancel — untrack it so its response is delivered, not dropped.
                tracker.discard(req_id)
            # Resolve the POST endpoint, waiting out a reconnect in progress.
            # endpoint_url is published lock-free, so a reconnect may clear it in
            # the TOCTOU window between this check and the read below; if the
            # capture comes back None, wait on ``ready`` (up to timeout_read) and
            # re-read once before giving up, rather than failing an otherwise
            # recoverable in-flight request with a spurious error.
            endpoint = state.endpoint_url
            if endpoint is None:
                if state.ready.wait(timeout=timeout_read):
                    endpoint = state.endpoint_url
                if endpoint is None:
                    _write_line(_error_response("SSE endpoint unavailable", req_id))
                    continue

            try:
                post_timeout = httpx.Timeout(
                    connect=timeout_connect,
                    read=timeout_read,
                    write=timeout_write,
                    pool=10,
                )
                # Honour Retry-After on 429 up to the cap; over-cap or
                # retries-exhausted falls through with the final 429 and
                # is surfaced to the caller by the generic 4xx branch
                # below (typescript-sdk#1892).
                for attempt in range(1, MAX_RETRIES + 1):
                    resp = client.post(
                        endpoint,
                        content=line,
                        headers=_snapshot_headers(),
                        timeout=post_timeout,
                    )
                    if resp.status_code != 429:
                        break
                    sleep_secs = _handle_rate_limit(resp.headers, attempt)
                    if sleep_secs is None:
                        break
                    log(
                        f"attempt {attempt}/{MAX_RETRIES} got HTTP 429, "
                        f"sleeping {sleep_secs:.1f}s before retry"
                    )
                    time.sleep(sleep_secs)

                if resp.status_code == 401 and token_refresher:
                    log("received 401, attempting token refresh")
                    new_headers = token_refresher()
                    if new_headers:
                        with headers_lock:
                            headers.update(new_headers)
                        resp = client.post(
                            endpoint,
                            content=line,
                            headers=_snapshot_headers(),
                            timeout=httpx.Timeout(
                                connect=timeout_connect,
                                read=timeout_read,
                                write=timeout_write,
                                pool=10,
                            ),
                        )
                    else:
                        log("token refresh failed, returning error")
                        _write_line(_error_response("authentication failed", req_id))
                        continue

                if resp.status_code == 403 and scope_upgrader:
                    required_scope = _parse_www_authenticate_scope(
                        resp.headers.get("www-authenticate")
                    )
                    if required_scope is not None:
                        log(
                            f"received 403 insufficient_scope "
                            f"(required: {required_scope}), attempting step-up"
                        )
                        new_headers = scope_upgrader(required_scope)
                        if new_headers:
                            with headers_lock:
                                headers.update(new_headers)
                            resp = client.post(
                                endpoint,
                                content=line,
                                headers=_snapshot_headers(),
                                timeout=httpx.Timeout(
                                    connect=timeout_connect,
                                    read=timeout_read,
                                    write=timeout_write,
                                    pool=10,
                                ),
                            )
                        else:
                            log(
                                "step-up authorization failed, returning error"
                            )
                            _write_line(_error_response("authorization failed", req_id))
                            continue

                if resp.status_code not in (200, 202):
                    log(f"POST returned HTTP {resp.status_code}")
                    _write_line(_error_response(f"HTTP {resp.status_code}", req_id))
            except httpx.HTTPError as e:
                log(f"POST failed: {e}")
                _write_line(_error_response(str(e), req_id))
    finally:
        state.stop.set()
        # Set stop first, then briefly join so the reader can exit its own
        # stream context when it next reaches a checkpoint. An *idle* GET (the
        # steady state — the reader is parked in iter_text() between events)
        # never reaches a checkpoint within the join, so client.close() below
        # then tears down the pool under it; that is safe — the reader catches
        # the resulting HTTPError and, because stop is already set, returns
        # without logging a reconnect. The daemon flag guarantees process exit
        # is never blocked regardless.
        reader.join(timeout=1.0)
        client.close()
