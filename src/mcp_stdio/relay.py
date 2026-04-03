"""Core relay logic: stdin JSON-RPC -> HTTP POST -> stdout."""

from __future__ import annotations

import json
import signal
import sys
import time
from typing import Any

import httpx

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


def send_request(
    client: httpx.Client,
    url: str,
    content: str,
    headers: dict[str, str],
) -> httpx.Response:
    """Send a request with retry on transient errors."""
    last_error: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return client.post(url, content=content, headers=headers)
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout) as e:
            last_error = e
            log(f"attempt {attempt}/{MAX_RETRIES} failed: {e}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
    raise last_error  # type: ignore[misc]


def test_connection(
    url: str,
    headers: dict[str, str],
    *,
    timeout_connect: float = 10,
    timeout_read: float = 120,
) -> bool:
    """Test MCP server connectivity by sending an initialize request.

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
                "clientInfo": {"name": "mcp-stdio", "version": "test"},
            },
        }
    )

    client = httpx.Client(
        timeout=httpx.Timeout(
            connect=timeout_connect, read=timeout_read, write=30, pool=10
        )
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
            log(
                f"✓ Capabilities: tools={tools}, resources={resources}, prompts={prompts}"
            )
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

            try:
                resp = send_request(client, url, line, req_headers)
            except Exception as e:
                log(f"request failed after retries: {e}")
                session_id = None
                print(_error_response(str(e), req_id), flush=True)
                continue

            # Session expired (404) — reset and retry
            if resp.status_code == 404 and session_id:
                log("session expired, resetting and retrying")
                session_id = None
                req_headers = dict(headers)
                try:
                    resp = send_request(client, url, line, req_headers)
                except Exception as e:
                    log(f"retry after session reset failed: {e}")
                    print(_error_response(str(e), req_id), flush=True)
                    continue

            # Track session ID
            if "mcp-session-id" in resp.headers:
                session_id = resp.headers["mcp-session-id"]

            # Parse response
            content_type = resp.headers.get("content-type", "")
            if "text/event-stream" in content_type:
                for event_line in resp.text.splitlines():
                    if event_line.startswith("data: "):
                        print(event_line[6:], flush=True)
            else:
                if resp.text.strip():
                    print(resp.text.strip(), flush=True)
    finally:
        client.close()
