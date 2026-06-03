"""Tests for the reverse gateway (``mcp-stdio serve``) — server.py."""

from __future__ import annotations

import json
import os
import sys
import threading
import time

import httpx
import pytest

from mcp_stdio import server

_BACKEND = [sys.executable, os.path.join(os.path.dirname(__file__), "_fake_backend.py")]


@pytest.fixture()
def gateway():
    """Start the gateway on an ephemeral port; yield its base MCP URL."""
    httpd, backend = server.build_server(_BACKEND, host="127.0.0.1", port=0)
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    url = f"http://{host}:{port}/mcp"
    try:
        yield url, backend
    finally:
        httpd.shutdown()
        backend.shutdown()
        httpd.server_close()


def _post(url: str, msg: dict) -> httpx.Response:
    return httpx.post(url, content=json.dumps(msg), timeout=10)


def test_request_response(gateway):
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"a": 1}})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"
    body = resp.json()
    assert body["id"] == 1
    assert body["result"]["echoed"] == {"a": 1}


def test_initialize_returns_protocol_version(gateway):
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": "init", "method": "initialize"})
    assert resp.status_code == 200
    assert resp.json()["result"]["protocolVersion"] == "2025-06-18"


def test_session_id_header_present_and_stable(gateway):
    url, _ = gateway
    r1 = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"})
    r2 = _post(url, {"jsonrpc": "2.0", "id": 2, "method": "echo"})
    sid1 = r1.headers.get("mcp-session-id")
    sid2 = r2.headers.get("mcp-session-id")
    assert sid1 and sid1 == sid2


def test_notification_returns_202(gateway):
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "method": "somenotify"})
    assert resp.status_code == 202


def test_client_response_returns_202(gateway):
    # A client answering a server-initiated request is a JSON-RPC response
    # (id + result, no method): the gateway forwards it one-way -> 202.
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": 99, "result": {"ok": True}})
    assert resp.status_code == 202


def test_batch_is_rejected(gateway):
    url, _ = gateway
    resp = httpx.post(url, content=json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "echo"}]), timeout=10)
    assert resp.status_code == 400


def test_invalid_json_returns_400(gateway):
    url, _ = gateway
    resp = httpx.post(url, content="{not json", timeout=10)
    assert resp.status_code == 400


def test_non_scalar_id_returns_400(gateway):
    # A non-scalar (unhashable) JSON-RPC id must not reach the pending-response
    # dict key (TypeError -> handler crash); the gateway rejects it as 400.
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": [1, 2], "method": "echo"})
    assert resp.status_code == 400


def test_wrong_path_returns_404(gateway):
    url, _ = gateway
    base = url.rsplit("/mcp", 1)[0]
    resp = httpx.post(base + "/nope", content="{}", timeout=10)
    assert resp.status_code == 404


def test_backend_timeout_returns_504(gateway, monkeypatch):
    url, _ = gateway
    monkeypatch.setattr(server, "_BACKEND_RESPONSE_TIMEOUT_SECS", 0.4)
    resp = _post(url, {"jsonrpc": "2.0", "id": 7, "method": "noreply"})
    assert resp.status_code == 504
    assert resp.json()["id"] == 7
    assert resp.json()["error"]["code"] == -32000


def test_get_sse_delivers_server_initiated(gateway):
    url, _ = gateway
    received: list[str] = []
    ready = threading.Event()

    def reader():
        with httpx.stream("GET", url, timeout=10) as r:
            ready.set()
            for line in r.iter_lines():
                if line.startswith("data: "):
                    received.append(line[len("data: ") :])
                    return

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    ready.wait(5)
    time.sleep(0.2)  # let the GET stream attach before we trigger a push
    _post(url, {"jsonrpc": "2.0", "method": "trigger_push"})
    t.join(5)
    assert received, "no SSE message received"
    msg = json.loads(received[0])
    assert msg["method"] == "notifications/message"
    assert msg["params"] == {"hello": "world"}


def test_delete_returns_200(gateway):
    url, _ = gateway
    resp = httpx.request("DELETE", url, timeout=10)
    assert resp.status_code == 200


def test_backend_death_then_request_fails(gateway):
    url, backend = gateway
    # Tell the backend to exit, then give the reader thread a moment to notice.
    _post(url, {"jsonrpc": "2.0", "method": "exit"})
    deadline = time.time() + 5
    while not backend.closed and time.time() < deadline:
        time.sleep(0.05)
    assert backend.closed
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"})
    assert resp.status_code == 503
    assert resp.json()["id"] == 1


# --- unit-level checks that don't need the HTTP server ---


def test_classify():
    assert server._classify({"method": "m", "id": 1}) == "request"
    assert server._classify({"method": "m"}) == "notification"
    assert server._classify({"id": 1, "result": {}}) == "response"
    assert server._classify({"id": 1, "error": {}}) == "response"
    assert server._classify({"id": 1}) == "invalid"
    assert server._classify([1, 2]) == "invalid"
    assert server._classify("x") == "invalid"


def test_serve_main_requires_command():
    with pytest.raises(SystemExit):
        server.serve_main(["--port", "9"])  # no backend command


def test_serve_main_rejects_bad_path():
    with pytest.raises(SystemExit):
        server.serve_main(["--path", "mcp", "--", "true"])  # path missing leading /
