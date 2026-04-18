"""Core relay logic: stdin JSON-RPC -> HTTP POST -> stdout."""

from __future__ import annotations

import json
import re
import signal
import sys
import threading
import time
from typing import Any
from urllib.parse import urljoin

import httpx

from mcp_stdio import __version__

MAX_RETRIES = 3
RETRY_DELAY = 1  # seconds

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


def _extract_id(line: str) -> Any:
    """Extract JSON-RPC id from request line."""
    try:
        return json.loads(line).get("id")
    except (json.JSONDecodeError, AttributeError):
        return None


def _error_response(message: str, req_id: Any = None) -> str:
    """Build a JSON-RPC error response."""
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": message},
            "id": req_id,
        }
    )


class _StreamResult:
    """Result of a streaming request."""

    __slots__ = ("session_id", "status_code", "www_authenticate")

    def __init__(
        self,
        session_id: str | None,
        status_code: int,
        www_authenticate: str | None = None,
    ):
        self.session_id = session_id
        self.status_code = status_code
        self.www_authenticate = www_authenticate


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


def _post_and_stream(
    client: httpx.Client,
    url: str,
    content: str,
    headers: dict[str, str],
    req_id: Any,
) -> _StreamResult | None:
    """Send a POST and stream the response to stdout with retry.

    Handles both SSE and JSON responses.  Returns a ``_StreamResult``
    on success (including non-200 status for caller to handle), or
    ``None`` when all retries are exhausted (error already printed).
    """
    last_error: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with client.stream("POST", url, content=content, headers=headers) as resp:
                session = resp.headers.get("mcp-session-id")
                www_auth = resp.headers.get("www-authenticate")

                if resp.status_code != 200:
                    resp.read()
                    return _StreamResult(session, resp.status_code, www_auth)

                content_type = resp.headers.get("content-type", "")
                if "text/event-stream" in content_type:
                    for line in resp.iter_lines():
                        if line.startswith("data: "):
                            print(line[6:], flush=True)
                else:
                    resp.read()
                    text = resp.text.strip()
                    if text:
                        print(text, flush=True)

                return _StreamResult(session, 200)
        except (
            httpx.ConnectError,
            httpx.ReadTimeout,
            httpx.WriteTimeout,
            httpx.ReadError,
        ) as e:
            last_error = e
            log(f"attempt {attempt}/{MAX_RETRIES} failed: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)

    log(f"request failed after retries: {last_error}")
    print(_error_response(str(last_error), req_id), flush=True)
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
            if resp.status_code != 200:
                return None, _StreamResult(session, resp.status_code, www_auth)

            content_type = resp.headers.get("content-type", "")
            if "text/event-stream" in content_type:
                for sse_line in resp.text.splitlines():
                    if sse_line.startswith("data: "):
                        try:
                            return (
                                json.loads(sse_line[len("data: "):]),
                                _StreamResult(session, 200),
                            )
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
        except (
            httpx.ConnectError,
            httpx.ReadTimeout,
            httpx.WriteTimeout,
            httpx.ReadError,
        ) as e:
            last_error = e
            log(f"attempt {attempt}/{MAX_RETRIES} failed: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)

    log(f"request failed after retries: {last_error}")
    print(_error_response(str(last_error), req_id), flush=True)
    return None, None


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
        return _post_and_stream(client, url, line, headers, req_id)

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
                return _post_and_stream(client, url, line, headers, req_id)
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
                print(json.dumps(parsed), flush=True)
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
    print(json.dumps(merged_response), flush=True)
    _ = truncated  # kept for future _meta annotation
    return _StreamResult(last_session, 200)


def _reinitialize(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
) -> str | None:
    """Send an initialize handshake to establish a new MCP session.

    Used to recover after a session expires (server returns 404 on the
    next request). Performs the full MCP initialize handshake:

    1. POST an ``initialize`` request to get a new session ID
    2. POST a ``notifications/initialized`` notification to signal
       readiness (required by the MCP spec before any other requests)

    Returns the new session ID on success, or None on failure. The
    initialize response payload is discarded — the caller only needs
    the session ID for subsequent requests.
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
        return None
    if resp.status_code != 200:
        log(f"re-initialize returned HTTP {resp.status_code}")
        return None
    new_session_id = resp.headers.get("mcp-session-id")
    if not new_session_id:
        log("re-initialize response missing mcp-session-id header")
        return None

    # MCP spec: send notifications/initialized before any other requests
    initialized_msg = json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    initialized_headers = dict(headers)
    initialized_headers["Mcp-Session-Id"] = new_session_id
    try:
        resp = client.post(url, content=initialized_msg, headers=initialized_headers)
    except httpx.HTTPError as e:
        log(f"notifications/initialized failed: {e}")
        return None
    if resp.status_code not in (200, 202):
        log(f"notifications/initialized returned HTTP {resp.status_code}")
        return None
    return new_session_id


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
            for event_line in resp.text.splitlines():
                if event_line.startswith("data: "):
                    try:
                        result_data = json.loads(event_line[6:])
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
    client = httpx.Client(
        timeout=httpx.Timeout(
            connect=timeout_connect,
            read=timeout_read,
            write=timeout_write,
            pool=10,
        )
    )

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            req_id = _extract_id(line)

            req_headers = dict(headers)
            if session_id:
                req_headers["Mcp-Session-Id"] = session_id

            def _dispatch(content: str, h: dict[str, str]) -> _StreamResult | None:
                detected = _detect_paginated_list(content)
                if detected:
                    return _paginate_and_stream(
                        client, url, content, h, req_id, detected[1]
                    )
                return _post_and_stream(client, url, content, h, req_id)

            result = _dispatch(line, req_headers)
            if result is None:
                # All retries exhausted — error already printed
                session_id = None
                continue

            # Token expired (401) — refresh and retry once
            if result.status_code == 401 and token_refresher:
                log("received 401, attempting token refresh")
                new_headers = token_refresher()
                if new_headers:
                    headers.update(new_headers)
                    req_headers = dict(headers)
                    if session_id:
                        req_headers["Mcp-Session-Id"] = session_id
                    result = _dispatch(line, req_headers)
                    if result is None:
                        continue
                else:
                    log("token refresh failed, returning error")
                    print(
                        _error_response("authentication failed", req_id),
                        flush=True,
                    )
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
                        req_headers = dict(headers)
                        if session_id:
                            req_headers["Mcp-Session-Id"] = session_id
                        result = _dispatch(line, req_headers)
                        if result is None:
                            continue
                    else:
                        log("step-up authorization failed, returning error")
                        print(
                            _error_response("authorization failed", req_id),
                            flush=True,
                        )
                        continue

            # Session expired (404) — reset, re-initialize, then retry
            if result.status_code == 404 and session_id:
                log("session expired, re-initializing and retrying")
                session_id = None
                new_session_id = _reinitialize(client, url, dict(headers))
                if new_session_id is None:
                    log("re-initialize failed, dropping request")
                    print(_error_response("session lost", req_id), flush=True)
                    continue
                session_id = new_session_id
                req_headers = dict(headers)
                req_headers["Mcp-Session-Id"] = session_id
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
                print(
                    _error_response(f"HTTP {result.status_code}", req_id),
                    flush=True,
                )
    finally:
        client.close()


class _SseState:
    """Shared state between SSE reader thread and main stdin loop."""

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
) -> None:
    """Reader thread: maintain SSE GET stream and dispatch events.

    Parses the SSE event stream per the WHATWG Server-Sent Events
    specification. The first ``endpoint`` event provides the POST URL
    (which may be relative — resolved with urljoin). Subsequent
    ``message`` events are JSON-RPC responses written to stdout.

    Reconnects automatically on disconnect.
    """
    while not state.stop.is_set():
        try:
            with client.stream("GET", url, headers=headers) as resp:
                if resp.status_code != 200:
                    log(f"SSE connection failed: HTTP {resp.status_code}")
                    state.ready.set()
                    return

                event_type = "message"
                data_lines: list[str] = []

                for line in resp.iter_lines():
                    if state.stop.is_set():
                        return

                    if line == "":
                        if data_lines:
                            data = "\n".join(data_lines)
                            if event_type == "endpoint":
                                resolved = urljoin(url, data)
                                state.endpoint_url = resolved
                                state.ready.set()
                                log(f"SSE endpoint: {resolved}")
                            elif event_type == "message":
                                print(data, flush=True)
                        event_type = "message"
                        data_lines = []
                    elif line.startswith(":"):
                        continue
                    elif line.startswith("event:"):
                        event_type = line[len("event:") :].strip()
                    elif line.startswith("data:"):
                        data_lines.append(line[len("data:") :].lstrip(" "))

                if state.stop.is_set():
                    return
                log("SSE stream ended, reconnecting")
                state.endpoint_url = None
                state.ready.clear()
                # Responsive reconnect delay: exits immediately on stop.
                if state.stop.wait(RETRY_DELAY):
                    return
        except httpx.HTTPError as e:
            if state.stop.is_set():
                return
            log(f"SSE disconnected, reconnecting: {e}")
            state.endpoint_url = None
            state.ready.clear()
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
            Set to ``None`` or ``0`` to restore the unbounded-read
            behaviour used before v0.6.0. Defaults to 300 seconds,
            matching the MCP Python SDK (#9).
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
    # its own. 0 is treated as "disabled" for parity with the old flag
    # semantics. POST requests use the separate timeout_read below.
    effective_sse_read = sse_read_timeout if sse_read_timeout else None
    client = httpx.Client(
        timeout=httpx.Timeout(
            connect=timeout_connect,
            read=effective_sse_read,
            write=timeout_write,
            pool=10,
        )
    )

    state = _SseState()
    reader = threading.Thread(
        target=_sse_reader_loop,
        args=(client, url, headers, state),
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

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            if state.endpoint_url is None:
                if not state.ready.wait(timeout=timeout_read):
                    req_id = _extract_id(line)
                    print(
                        _error_response("SSE endpoint unavailable", req_id),
                        flush=True,
                    )
                    continue

            req_id = _extract_id(line)
            endpoint = state.endpoint_url
            if endpoint is None:
                print(
                    _error_response("SSE endpoint unavailable", req_id),
                    flush=True,
                )
                continue

            try:
                resp = client.post(
                    endpoint,
                    content=line,
                    headers=headers,
                    timeout=httpx.Timeout(
                        connect=timeout_connect,
                        read=timeout_read,
                        write=timeout_write,
                        pool=10,
                    ),
                )

                if resp.status_code == 401 and token_refresher:
                    log("received 401, attempting token refresh")
                    new_headers = token_refresher()
                    if new_headers:
                        headers.update(new_headers)
                        resp = client.post(
                            endpoint,
                            content=line,
                            headers=headers,
                            timeout=httpx.Timeout(
                                connect=timeout_connect,
                                read=timeout_read,
                                write=timeout_write,
                                pool=10,
                            ),
                        )
                    else:
                        log("token refresh failed, returning error")
                        print(
                            _error_response("authentication failed", req_id),
                            flush=True,
                        )
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
                            headers.update(new_headers)
                            resp = client.post(
                                endpoint,
                                content=line,
                                headers=headers,
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
                            print(
                                _error_response("authorization failed", req_id),
                                flush=True,
                            )
                            continue

                if resp.status_code not in (200, 202):
                    log(f"POST returned HTTP {resp.status_code}")
                    print(
                        _error_response(
                            f"HTTP {resp.status_code}", req_id
                        ),
                        flush=True,
                    )
            except httpx.HTTPError as e:
                log(f"POST failed: {e}")
                print(_error_response(str(e), req_id), flush=True)
    finally:
        state.stop.set()
        client.close()
