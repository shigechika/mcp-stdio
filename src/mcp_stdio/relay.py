"""Core relay logic: stdin JSON-RPC -> HTTP POST -> stdout."""

from __future__ import annotations

import json
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

    __slots__ = ("session_id", "status_code")

    def __init__(self, session_id: str | None, status_code: int):
        self.session_id = session_id
        self.status_code = status_code


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

                if resp.status_code != 200:
                    resp.read()
                    return _StreamResult(session, resp.status_code)

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
            log(f"✗ HTTP {resp.status_code}: {resp.text[:200]}")
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

            result = _post_and_stream(client, url, line, req_headers, req_id)
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
                    result = _post_and_stream(client, url, line, req_headers, req_id)
                    if result is None:
                        continue
                else:
                    log("token refresh failed, returning error")
                    print(
                        _error_response("authentication failed", req_id),
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
                result = _post_and_stream(client, url, line, req_headers, req_id)
                if result is None:
                    continue

            if result.session_id:
                session_id = result.session_id
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
    token_refresher: Any = None,
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
        token_refresher: Optional callable that returns updated headers
            on successful token refresh, or None on failure. Called when
            the server returns HTTP 401 on POST.
    """

    def _shutdown(signum: int, _: Any) -> None:
        log(f"received signal {signum}, shutting down")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log(f"connecting to {url} (SSE transport)")

    # SSE GET is long-lived; use no read timeout for streaming.
    # POST uses a bounded timeout via a separate per-request call.
    client = httpx.Client(
        timeout=httpx.Timeout(
            connect=timeout_connect,
            read=None,
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
