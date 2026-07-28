"""Tests for the reverse gateway (``mcp-stdio serve``) — server.py."""

from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from mcp_stdio import oauth as client_oauth
from mcp_stdio import server

_BACKEND = [sys.executable, os.path.join(os.path.dirname(__file__), "_fake_backend.py")]


@pytest.fixture()
def gateway():
    """Start the gateway on an ephemeral port; yield its base MCP URL."""
    httpd, registry = server.build_server(_BACKEND, host="127.0.0.1", port=0)
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    url = f"http://{host}:{port}/mcp"
    try:
        yield url, registry
    finally:
        httpd.shutdown()
        registry.shutdown_all()
        httpd.server_close()


def _post(url: str, msg: dict, sid: str | None = None) -> httpx.Response:
    headers = {"Mcp-Session-Id": sid} if sid else {}
    return httpx.post(url, content=json.dumps(msg), headers=headers, timeout=10)


def _init(url: str, headers: dict | None = None) -> tuple[str | None, httpx.Response]:
    """POST ``initialize`` to open a session; return (session_id, response)."""
    resp = httpx.post(
        url,
        content=json.dumps({"jsonrpc": "2.0", "id": "init", "method": "initialize"}),
        headers=headers or {},
        timeout=10,
    )
    return resp.headers.get("mcp-session-id"), resp


def test_request_response(gateway):
    url, _ = gateway
    sid, _ = _init(url)
    resp = _post(
        url, {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"a": 1}}, sid
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"
    body = resp.json()
    assert body["id"] == 1
    assert body["result"]["echoed"] == {"a": 1}


def test_initialize_returns_protocol_version(gateway):
    url, _ = gateway
    _, resp = _init(url)
    assert resp.status_code == 200
    assert resp.json()["result"]["protocolVersion"] == "2025-06-18"


def test_initialize_assigns_session(gateway):
    url, registry = gateway
    sid, resp = _init(url)
    assert resp.status_code == 200
    assert sid  # the gateway minted an Mcp-Session-Id
    assert registry.count == 1


def test_session_id_per_initialize(gateway):
    # Each initialize starts a NEW session with its own id (was a constant id
    # under the old single-backend model).
    url, registry = gateway
    sid1, _ = _init(url)
    sid2, _ = _init(url)
    assert sid1 and sid2 and sid1 != sid2
    assert registry.count == 2


def test_two_initializes_distinct_children(gateway):
    # Two sessions -> two distinct child processes (process-boundary isolation).
    url, _ = gateway
    sid1, _ = _init(url)
    sid2, _ = _init(url)
    p1 = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"}, sid1).json()[
        "result"
    ]["pid"]
    p2 = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"}, sid2).json()[
        "result"
    ]["pid"]
    assert p1 != p2


def test_no_cross_session_id_leak(gateway):
    # Two sessions both use JSON-RPC id=1; each must get ITS OWN child's
    # response, never the other's (the single-backend model could cross them).
    url, _ = gateway
    sid_a, _ = _init(url)
    sid_b, _ = _init(url)
    ra = _post(
        url,
        {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"who": "A"}},
        sid_a,
    ).json()
    rb = _post(
        url,
        {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"who": "B"}},
        sid_b,
    ).json()
    assert ra["result"]["echoed"] == {"who": "A"}
    assert rb["result"]["echoed"] == {"who": "B"}
    assert ra["result"]["pid"] != rb["result"]["pid"]


def test_reused_id_sequential_same_session(gateway):
    # A client that reuses JSON-RPC id=1 across SEQUENTIAL requests on ONE
    # session (claude-ai-mcp#539: some clients pin id=1 for every call) must get
    # each request's OWN response. serve correlates responses per session-child
    # by id and pops the pending id on each reply, so sequential reuse (one
    # request outstanding at a time) is unambiguous. NB: two requests with the
    # SAME id in flight AT ONCE are ambiguous by construction — the backend's two
    # replies both carry that id — and send_request resolves _pending[req_id]
    # last-writer-wins, so one caller can receive the other's reply (a real
    # cross-wire, not a safe timeout). This test covers only the well-defined
    # sequential case; ids must be unique per outstanding request.
    url, _ = gateway
    sid, _ = _init(url)
    r1 = _post(
        url, {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"n": 1}}, sid
    ).json()
    r2 = _post(
        url, {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"n": 2}}, sid
    ).json()
    r3 = _post(
        url, {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"n": 3}}, sid
    ).json()
    assert r1["id"] == 1 and r2["id"] == 1 and r3["id"] == 1
    assert r1["result"]["echoed"] == {"n": 1}
    assert r2["result"]["echoed"] == {"n": 2}
    assert r3["result"]["echoed"] == {"n": 3}
    # Same session -> same child throughout (session state persists across the
    # reused id, unlike a client that mints a fresh session per call).
    assert r1["result"]["pid"] == r2["result"]["pid"] == r3["result"]["pid"]


def _wait_in_flight(proc: server.BackendProcess, req_id) -> None:
    """Poll until ``req_id`` is registered in flight on ``proc``."""
    for _ in range(600):
        with proc._lock:
            if req_id in proc._pending:
                return
        time.sleep(0.005)
    pytest.fail(f"request id {req_id!r} never registered in flight")


def test_duplicate_in_flight_id_rejected():
    # Two requests sharing a JSON-RPC id IN FLIGHT at once on one session-child,
    # with DIFFERENT payloads, are ambiguous — both backend replies carry that
    # id. MCP 2025-06-18 forbids reusing a request id within a session, so serve
    # rejects the second rather than overwriting the pending slot, which would
    # cross-wire the first reply to the second waiter (claude-ai-mcp#539). A
    # SAME-payload duplicate is a different case — see
    # test_duplicate_in_flight_id_same_payload_piggybacks below (mcp-stdio#331).
    # The first request (noreply) is given a long timeout so it stays reliably
    # in flight for the whole test (a short timeout could pop _pending before
    # the duplicate runs under heavy CI load and mask the collision);
    # shutdown() then unblocks it.
    proc = server.BackendProcess(_BACKEND)
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            first = ex.submit(
                proc.send_request,
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "noreply"}),
                1,
                30.0,
            )
            _wait_in_flight(proc, 1)
            with pytest.raises(server._DuplicateInFlightId) as excinfo:
                proc.send_request(
                    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "echo"}), 1, 1.0
                )
            # The exception names both colliding calls so the HTTP handler can
            # log which methods shared the id (bare 409s are undiagnosable).
            assert excinfo.value.in_flight_method == "noreply"
            assert excinfo.value.rejected_method == "echo"
            # Unblock the long-timeout first waiter (fail-all wakes it -> None).
            proc.shutdown()
            assert first.result() is None
    finally:
        proc.shutdown()


def test_duplicate_in_flight_id_same_payload_piggybacks():
    # mcp-stdio#331: after a gateway restart / idle-reclaim, a client's
    # reconnect burst can re-fire a request whose id collides with itself
    # while the first copy is still outstanding. Since the payload is IDENTICAL
    # (a retry, not a protocol violation), the second call must piggyback on
    # the first's pending slot and get the SAME backend reply — not 409 — and
    # the backend must see only ONE copy of the request. slow_echo's `calls`
    # counter proves the dispatch count deterministically: the shared reply
    # reports calls=1, and a follow-up request reports calls=2 (a regression
    # to double dispatch would make it 3).
    proc = server.BackendProcess(_BACKEND)
    try:
        line = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "slow_echo", "params": {"n": 1}}
        )
        with ThreadPoolExecutor(max_workers=2) as ex:
            first = ex.submit(proc.send_request, line, 1, 5.0)
            _wait_in_flight(proc, 1)
            second = ex.submit(proc.send_request, line, 1, 5.0)
            r1, r2 = first.result(), second.result()
        assert r1 is not None and r2 is not None
        assert r1 == r2  # both observed the one backend reply
        assert json.loads(r1)["result"]["calls"] == 1
        # The slot must be retired after both callers are done (no leak).
        with proc._lock:
            assert 1 not in proc._pending
        followup = proc.send_request(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "slow_echo",
                    "params": {"delay": 0},
                }
            ),
            2,
            5.0,
        )
        assert json.loads(followup)["result"]["calls"] == 2
    finally:
        proc.shutdown()


def test_duplicate_in_flight_id_reserialized_retry_piggybacks():
    # A retry re-serialized by the client with a different JSON key order is
    # the same message; matching must be semantic (parsed equality), not byte
    # equality, or the 409 churn mcp-stdio#331 removes would persist for any
    # client library that does not preserve key order on retry.
    proc = server.BackendProcess(_BACKEND)
    try:
        line1 = '{"jsonrpc": "2.0", "id": 1, "method": "slow_echo", "params": {"n": 1}}'
        line2 = '{"id": 1, "params": {"n": 1}, "method": "slow_echo", "jsonrpc": "2.0"}'
        with ThreadPoolExecutor(max_workers=2) as ex:
            first = ex.submit(proc.send_request, line1, 1, 5.0)
            _wait_in_flight(proc, 1)
            second = ex.submit(proc.send_request, line2, 1, 5.0)
            r1, r2 = first.result(), second.result()
        assert r1 is not None and r1 == r2
        assert json.loads(r1)["result"]["calls"] == 1
    finally:
        proc.shutdown()


def test_piggybacked_retry_survives_owner_timeout():
    # The FIRST caller's own timeout must not orphan a still-waiting retry:
    # the slot is retired by its LAST waiter, so it stays registered, the late
    # reply reaches the retry (instead of leaking to SSE as an uncorrelated
    # response), and has_pending stays True (keeping the idle reaper away).
    # Each waiter keeps its own deadline: the first caller still times out.
    proc = server.BackendProcess(_BACKEND)
    try:
        line = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "slow_echo", "params": {"delay": 1.0}}
        )
        with ThreadPoolExecutor(max_workers=2) as ex:
            first = ex.submit(proc.send_request, line, 1, 0.3)  # expires at 0.3s
            _wait_in_flight(proc, 1)
            second = ex.submit(proc.send_request, line, 1, 5.0)  # attaches now
            r1, r2 = first.result(), second.result()
        assert r1 is None  # its own deadline passed before the 1.0s reply
        assert r2 is not None  # the retry still received the reply...
        assert json.loads(r2)["result"]["calls"] == 1  # ...from the ONE dispatch
        with proc._lock:
            assert 1 not in proc._pending  # last waiter retired the slot
    finally:
        proc.shutdown()


def test_duplicate_in_flight_id_same_payload_returns_200_over_http(gateway):
    # HTTP-level counterpart of test_duplicate_in_flight_id_same_payload_piggybacks:
    # a client that fires the identical request twice under one id while the
    # first is still outstanding (the mcp-stdio#331 reconnect-burst shape) must
    # get 200 with the SAME result both times, never the 409 a genuinely
    # different duplicate payload still gets. calls=1 in the shared reply
    # proves the backend saw one dispatch (double dispatch would surface as
    # differing bodies or calls=2 here).
    url, registry = gateway
    sid, _ = _init(url)
    backend = registry.get(sid)
    msg = {"jsonrpc": "2.0", "id": 1, "method": "slow_echo", "params": {"n": 1}}
    with ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(_post, url, msg, sid)
        # Wait until the first request is registered in flight (a fixed sleep
        # can fire early under CI load and dodge the piggyback path).
        for _ in range(600):
            if backend.has_pending:
                break
            time.sleep(0.005)
        else:  # pragma: no cover - defensive
            pytest.fail("first request never registered in flight")
        f2 = ex.submit(_post, url, msg, sid)
        r1, r2 = f1.result(), f2.result()
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r1.json() == r2.json()
    assert r1.json()["result"]["calls"] == 1


def test_duplicate_in_flight_id_different_payload_409_and_logged(gateway, capsys):
    # HTTP-level counterpart of test_duplicate_in_flight_id_rejected, plus the
    # diagnostic contract: the access log alone shows a bare 409 and cannot
    # tell which two calls collided (needed live 2026-07-27 to tell "client
    # re-fired a request" from "two gateway-side nodes share an id counter"),
    # so the rejection must log the conflicting id and both methods on ONE
    # line — injection-safe even for a hostile method name.
    url, registry = gateway
    sid, _ = _init(url)
    backend = registry.get(sid)
    first = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "slow_echo",
        "params": {"delay": 1.0},
    }
    hostile = {"jsonrpc": "2.0", "id": 1, "method": "echo\nforged"}
    with ThreadPoolExecutor(max_workers=1) as ex:
        f1 = ex.submit(_post, url, first, sid)
        for _ in range(600):
            if backend.has_pending:
                break
            time.sleep(0.005)
        else:  # pragma: no cover - defensive
            pytest.fail("first request never registered in flight")
        r2 = _post(url, hostile, sid)
        r1 = f1.result()
    assert r2.status_code == 409
    assert r1.status_code == 200  # the in-flight request is unaffected
    err = capsys.readouterr().err
    hits = [ln for ln in err.splitlines() if "duplicate in-flight id" in ln]
    # Exactly one line: the CR/LF in the hostile method must not split it.
    assert len(hits) == 1
    assert "duplicate in-flight id 1 on session" in hits[0]
    assert "in-flight='slow_echo'" in hits[0]
    assert "rejected='echo\\nforged'" in hits[0]
    assert "-> 409" in hits[0]


def test_notification_returns_202(gateway):
    url, _ = gateway
    sid, _ = _init(url)
    resp = _post(url, {"jsonrpc": "2.0", "method": "somenotify"}, sid)
    assert resp.status_code == 202


def test_client_response_returns_202(gateway):
    # A client answering a server-initiated request is a JSON-RPC response
    # (id + result, no method): the gateway forwards it one-way -> 202.
    url, _ = gateway
    sid, _ = _init(url)
    resp = _post(url, {"jsonrpc": "2.0", "id": 99, "result": {"ok": True}}, sid)
    assert resp.status_code == 202


def test_sessionless_non_init_returns_400(gateway):
    # MCP spec: a non-initialize request without an Mcp-Session-Id -> 400.
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"})
    assert resp.status_code == 400


def test_unknown_session_returns_404(gateway):
    # MCP spec: an unknown/terminated session id -> 404 (drives re-initialize).
    url, _ = gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"}, "deadbeef" * 4)
    assert resp.status_code == 404


def test_batch_is_rejected(gateway):
    url, _ = gateway
    resp = httpx.post(
        url,
        content=json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "echo"}]),
        timeout=10,
    )
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
    sid, _ = _init(url)
    resp = _post(url, {"jsonrpc": "2.0", "id": 7, "method": "noreply"}, sid)
    assert resp.status_code == 504
    assert resp.json()["id"] == 7
    assert resp.json()["error"]["code"] == -32000


def test_get_sse_delivers_server_initiated(gateway):
    url, _ = gateway
    sid, _ = _init(url)
    received: list[str] = []
    ready = threading.Event()

    def reader():
        with httpx.stream("GET", url, headers={"Mcp-Session-Id": sid}, timeout=10) as r:
            ready.set()
            for line in r.iter_lines():
                if line.startswith("data: "):
                    received.append(line[len("data: ") :])
                    return

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    ready.wait(5)
    time.sleep(0.2)  # let the GET stream attach before we trigger a push
    _post(url, {"jsonrpc": "2.0", "method": "trigger_push"}, sid)
    t.join(5)
    assert received, "no SSE message received"
    msg = json.loads(received[0])
    assert msg["method"] == "notifications/message"
    assert msg["params"] == {"hello": "world"}


def test_get_sse_unknown_session_returns_404(gateway):
    url, _ = gateway
    resp = httpx.get(url, headers={"Mcp-Session-Id": "nope" * 8}, timeout=10)
    assert resp.status_code == 404


def test_get_sse_without_session_returns_400(gateway):
    # MCP spec item 2: a sessionless GET (like a sessionless POST) -> 400.
    url, _ = gateway
    resp = httpx.get(url, timeout=10)
    assert resp.status_code == 400


def test_delete_reaps_session(gateway):
    url, registry = gateway
    sid, _ = _init(url)
    assert registry.count == 1
    resp = httpx.request("DELETE", url, headers={"Mcp-Session-Id": sid}, timeout=10)
    assert resp.status_code == 200
    assert registry.count == 0
    # The terminated session id is now unknown -> 404.
    again = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"}, sid)
    assert again.status_code == 404


def test_delete_without_session_id_returns_400(gateway):
    url, _ = gateway
    resp = httpx.request("DELETE", url, timeout=10)
    assert resp.status_code == 400


def test_delete_unknown_session_returns_404(gateway):
    url, _ = gateway
    resp = httpx.request(
        "DELETE", url, headers={"Mcp-Session-Id": "x" * 32}, timeout=10
    )
    assert resp.status_code == 404


def test_backend_death_then_request_fails(gateway):
    url, registry = gateway
    sid, _ = _init(url)
    backend = registry.get(sid)
    # Tell the backend to exit, then give the reader thread a moment to notice.
    _post(url, {"jsonrpc": "2.0", "method": "exit"}, sid)
    deadline = time.time() + 5
    while not backend.closed and time.time() < deadline:
        time.sleep(0.05)
    assert backend.closed
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"}, sid)
    assert resp.status_code == 503
    assert resp.json()["id"] == 1
    # The dead session is reaped, so the slot is reclaimed and the next request
    # on that id gets 404 (the client then re-initializes) rather than 503.
    assert registry.count == 0
    again = _post(url, {"jsonrpc": "2.0", "id": 2, "method": "echo"}, sid)
    assert again.status_code == 404


def test_registry_cap_rejects_beyond_max():
    # Unit-level: the registry returns None past the concurrent-session cap.
    reg = server.SessionRegistry(_BACKEND, max_sessions=2)
    try:
        assert reg.create() is not None
        assert reg.create() is not None
        assert reg.create() is None  # cap reached
        assert reg.count == 2
    finally:
        reg.shutdown_all()
    assert reg.count == 0


def test_session_cap_returns_503():
    # HTTP-level: an initialize past the cap gets 503.
    httpd, registry = server.build_server(
        _BACKEND, host="127.0.0.1", port=0, max_sessions=1
    )
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    url = f"http://{host}:{port}/mcp"
    try:
        sid1, r1 = _init(url)
        assert r1.status_code == 200 and sid1
        _, r2 = _init(url)
        assert r2.status_code == 503
    finally:
        httpd.shutdown()
        registry.shutdown_all()
        httpd.server_close()


def test_reap_idle_evicts_after_ttl():
    # Unit-level with an injected clock: a session idle past the TTL is evicted
    # and its child shut down.
    clock = [1000.0]
    reg = server.SessionRegistry(_BACKEND, idle_ttl=30, now=lambda: clock[0])
    try:
        _, backend = reg.create()
        assert reg.count == 1
        clock[0] += 20  # within TTL
        assert reg.reap_idle() == 0
        assert reg.count == 1
        clock[0] += 20  # 40s since last activity > 30s TTL
        assert reg.reap_idle() == 1
        assert reg.count == 0
        assert backend.closed
    finally:
        reg.shutdown_all()


def test_active_session_survives_reap():
    # get() touches last_active, so an actively-used session is never reaped.
    clock = [1000.0]
    reg = server.SessionRegistry(_BACKEND, idle_ttl=30, now=lambda: clock[0])
    try:
        sid, _ = reg.create()
        clock[0] += 25
        assert reg.get(sid) is not None  # touch -> last_active = 1025
        clock[0] += 10  # only 10s since the touch
        assert reg.reap_idle() == 0
        assert reg.count == 1
    finally:
        reg.shutdown_all()


def test_reap_idle_drops_dead_child_even_without_ttl():
    # A child that has exited is reaped regardless of TTL (slot reclaimed).
    reg = server.SessionRegistry(_BACKEND, idle_ttl=0)
    try:
        _, backend = reg.create()
        backend.shutdown()  # simulate the child dying
        assert backend.closed
        assert reg.reap_idle() == 1
        assert reg.count == 0
    finally:
        reg.shutdown_all()


def test_start_reaper_noop_when_ttl_disabled():
    reg = server.SessionRegistry(_BACKEND, idle_ttl=0)
    reg.start_reaper()
    assert reg._reaper is None  # no thread when eviction is disabled
    reg.stop_reaper()  # safe no-op


def test_reaper_thread_evicts_idle_session():
    # The background reaper thread evicts an idle session on its own.
    reg = server.SessionRegistry(_BACKEND, idle_ttl=0.5)
    reg.start_reaper()
    try:
        reg.create()
        assert reg.count == 1
        deadline = time.time() + 5
        while reg.count > 0 and time.time() < deadline:
            time.sleep(0.05)
        assert reg.count == 0
    finally:
        reg.shutdown_all()


def test_serve_main_rejects_zero_max_sessions():
    with pytest.raises(SystemExit):
        server.serve_main(["--max-sessions", "0", "--", "true"])


def test_serve_main_rejects_negative_idle_ttl():
    with pytest.raises(SystemExit):
        server.serve_main(["--session-idle-ttl", "-1", "--", "true"])


def test_serve_main_rejects_non_finite_idle_ttl():
    # inf/nan parse as floats but would arm a reaper that never evicts.
    for bad in ("inf", "nan"):
        with pytest.raises(SystemExit):
            server.serve_main(["--session-idle-ttl", bad, "--", "true"])


def test_serve_main_rejects_negative_max_sessions_per_owner():
    with pytest.raises(SystemExit):
        server.serve_main(["--max-sessions-per-owner", "-1", "--", "true"])


def test_per_owner_reclaims_prior_session_on_reinit():
    # With a per-owner cap of 1, a fresh create for the same owner evicts that
    # owner's prior session (the ghost a reconnecting client leaves behind) and
    # shuts its child down.
    reg = server.SessionRegistry(_BACKEND, max_sessions_per_owner=1)
    try:
        sid1, backend1 = reg.create(owner="alice")
        sid2, backend2 = reg.create(owner="alice")
        assert sid1 != sid2
        assert reg.count == 1
        assert reg.get(sid1, "alice") is None  # prior session reclaimed
        assert reg.get(sid2, "alice") is not None  # new session live
        assert backend1.closed  # its child was torn down
        assert not backend2.closed
    finally:
        reg.shutdown_all()


def test_per_owner_lru_evicts_least_recently_active():
    # Cap of 2: the third create evicts the LEAST recently active of the owner's
    # sessions, not an arbitrary one.
    clock = [1000.0]
    reg = server.SessionRegistry(
        _BACKEND, max_sessions_per_owner=2, now=lambda: clock[0]
    )
    try:
        sid1, _ = reg.create(owner="alice")  # last_active 1000
        clock[0] += 10
        sid2, _ = reg.create(owner="alice")  # last_active 1010
        clock[0] += 10
        assert reg.get(sid1, "alice") is not None  # touch sid1 -> 1020
        clock[0] += 10
        sid3, _ = reg.create(owner="alice")  # now sid2 (1010) is the LRU
        assert reg.count == 2
        assert reg.get(sid2, "alice") is None  # LRU evicted
        assert reg.get(sid1, "alice") is not None  # recently touched survives
        assert reg.get(sid3, "alice") is not None
    finally:
        reg.shutdown_all()


def test_per_owner_does_not_touch_other_owners():
    # alice re-initializing never disturbs bob's session.
    reg = server.SessionRegistry(_BACKEND, max_sessions_per_owner=1)
    try:
        _, _ = reg.create(owner="alice")
        sid_bob, _ = reg.create(owner="bob")
        reg.create(owner="alice")  # reclaims alice's, not bob's
        assert reg.get(sid_bob, "bob") is not None
        assert reg.count == 2  # one alice + one bob
    finally:
        reg.shutdown_all()


def test_per_owner_exempts_static_and_open_gateway():
    # owner None (open gateway) and the shared static-token principal are NOT
    # capped: many distinct clients legitimately share them.
    reg = server.SessionRegistry(_BACKEND, max_sessions_per_owner=1)
    try:
        reg.create(owner=None)
        reg.create(owner=None)
        reg.create(owner=server._STATIC_PRINCIPAL)
        reg.create(owner=server._STATIC_PRINCIPAL)
        assert reg.count == 4  # none reclaimed
    finally:
        reg.shutdown_all()


def test_per_owner_reclaims_under_saturated_global_cap():
    # Regression for the ordering bug: per-owner reclamation must run BEFORE the
    # global-cap check, so an owner whose OWN ghost fills the only slot still
    # reconnects instead of getting locked out until the idle reaper fires.
    reg = server.SessionRegistry(_BACKEND, max_sessions=1, max_sessions_per_owner=1)
    try:
        sid1, backend1 = reg.create(owner="alice")  # fills the single slot
        assert reg.count == 1
        created = reg.create(owner="alice")  # global cap saturated...
        assert created is not None  # ...but alice's ghost is
        sid2, _ = created  # reclaimed, so this wins
        assert sid1 != sid2
        assert reg.count == 1
        assert reg.get(sid1, "alice") is None  # old slot reclaimed
        assert reg.get(sid2, "alice") is not None
        assert backend1.closed
    finally:
        reg.shutdown_all()


def test_per_owner_reclaims_under_saturation_with_other_owners():
    # Saturated by two distinct owners: alice re-initializing reclaims her own
    # session (not bob's) and lands the new one, staying within max_sessions.
    reg = server.SessionRegistry(_BACKEND, max_sessions=2, max_sessions_per_owner=1)
    try:
        sid_a1, _ = reg.create(owner="alice")
        sid_b, _ = reg.create(owner="bob")
        assert reg.count == 2  # saturated
        created = reg.create(owner="alice")
        assert created is not None
        sid_a2, _ = created
        assert reg.count == 2
        assert reg.get(sid_a1, "alice") is None  # alice's old one gone
        assert reg.get(sid_b, "bob") is not None  # bob untouched
        assert reg.get(sid_a2, "alice") is not None
    finally:
        reg.shutdown_all()


def test_per_owner_disabled_by_default():
    # Default (0) preserves today's behavior: same-owner sessions coexist.
    reg = server.SessionRegistry(_BACKEND)
    try:
        sid1, _ = reg.create(owner="alice")
        sid2, _ = reg.create(owner="alice")
        assert reg.count == 2
        assert reg.get(sid1, "alice") is not None
        assert reg.get(sid2, "alice") is not None
    finally:
        reg.shutdown_all()


def test_idle_eviction_disabled_keeps_live_session():
    # ttl=0 disables idle eviction: a live, arbitrarily-idle session survives.
    clock = [1000.0]
    reg = server.SessionRegistry(_BACKEND, idle_ttl=0, now=lambda: clock[0])
    try:
        reg.create()
        clock[0] += 10_000
        assert reg.reap_idle() == 0
        assert reg.count == 1
    finally:
        reg.shutdown_all()


def test_in_flight_request_not_reaped():
    # A session with a request in flight is not idle, even past the TTL.
    clock = [1000.0]
    reg = server.SessionRegistry(_BACKEND, idle_ttl=10, now=lambda: clock[0])
    try:
        _, backend = reg.create()
        done = threading.Event()

        def slow():
            backend.send_request(
                '{"jsonrpc": "2.0", "id": 1, "method": "noreply"}', 1, 2.0
            )
            done.set()

        threading.Thread(target=slow, daemon=True).start()
        for _ in range(100):
            if backend.has_pending:
                break
            time.sleep(0.02)
        assert backend.has_pending
        clock[0] += 100  # well past the TTL
        assert reg.reap_idle() == 0  # the in-flight request protects it
        assert reg.count == 1
        assert done.wait(5)  # the request times out -> pending cleared
        assert not backend.has_pending
        clock[0] += 100
        assert reg.reap_idle() == 1  # now genuinely idle
    finally:
        reg.shutdown_all()


def test_build_server_idle_ttl_evicts_http_session():
    # End-to-end: idle_ttl threaded through build_server + start_reaper evicts
    # an idle HTTP session, after which its id 404s.
    httpd, registry = server.build_server(
        _BACKEND, host="127.0.0.1", port=0, idle_ttl=0.5
    )
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    registry.start_reaper()
    url = f"http://{host}:{port}/mcp"
    try:
        sid, r = _init(url)
        assert r.status_code == 200 and registry.count == 1
        deadline = time.time() + 5
        while registry.count > 0 and time.time() < deadline:
            time.sleep(0.05)
        assert registry.count == 0
        again = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"}, sid)
        assert again.status_code == 404
    finally:
        httpd.shutdown()
        registry.shutdown_all()
        httpd.server_close()


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


# --- static-bearer-token Resource Server + RFC 9728 metadata ---

_TOKEN = "s3cr3t-token"


@pytest.fixture()
def auth_gateway():
    """A gateway protected by a static bearer token."""
    httpd, registry = server.build_server(
        _BACKEND, host="127.0.0.1", port=0, auth_token=_TOKEN
    )
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    url = f"http://{host}:{port}/mcp"
    try:
        yield url, registry
    finally:
        httpd.shutdown()
        registry.shutdown_all()
        httpd.server_close()


def _base(url: str) -> str:
    return url.rsplit("/mcp", 1)[0]


def test_auth_missing_token_returns_401_with_metadata_hint(auth_gateway):
    url, _ = auth_gateway
    resp = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "echo"})
    assert resp.status_code == 401
    wa = resp.headers.get("www-authenticate", "")
    assert wa.startswith("Bearer ")
    assert "resource_metadata=" in wa
    assert "/.well-known/oauth-protected-resource/mcp" in wa


def test_auth_wrong_token_returns_401(auth_gateway):
    url, _ = auth_gateway
    resp = httpx.post(
        url,
        content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "echo"}),
        headers={"Authorization": "Bearer nope"},
        timeout=10,
    )
    assert resp.status_code == 401


def test_auth_valid_token_returns_200(auth_gateway):
    url, _ = auth_gateway
    auth = {"Authorization": f"Bearer {_TOKEN}"}
    sid, _ = _init(url, headers=auth)
    resp = httpx.post(
        url,
        content=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"a": 1}}
        ),
        headers={**auth, "Mcp-Session-Id": sid},
        timeout=10,
    )
    assert resp.status_code == 200
    assert resp.json()["result"]["echoed"] == {"a": 1}


def test_get_sse_requires_auth(auth_gateway):
    url, _ = auth_gateway
    resp = httpx.get(url, timeout=10)  # no token on the MCP path
    assert resp.status_code == 401


def test_prm_served_without_token(auth_gateway):
    url, _ = auth_gateway
    base = _base(url)
    # Path-specific form (RFC 9728 Sec. 3.1).
    resp = httpx.get(base + "/.well-known/oauth-protected-resource/mcp", timeout=10)
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource"].endswith("/mcp")
    assert body["bearer_methods_supported"] == ["header"]
    assert "authorization_servers" not in body  # none without the embedded AS
    # Bare form is also served.
    resp2 = httpx.get(base + "/.well-known/oauth-protected-resource", timeout=10)
    assert resp2.status_code == 200


def test_prm_404_when_auth_disabled(gateway):
    url, _ = gateway
    resp = httpx.get(
        _base(url) + "/.well-known/oauth-protected-resource/mcp", timeout=10
    )
    assert resp.status_code == 404


def test_prm_prefix_overmatch_not_served(auth_gateway):
    # A path that merely shares the well-known prefix (".../-resource-evil")
    # must NOT be treated as the metadata endpoint.
    url, _ = auth_gateway
    resp = httpx.get(
        _base(url) + "/.well-known/oauth-protected-resource-evil", timeout=10
    )
    assert resp.status_code == 404
    assert "bearer_methods_supported" not in resp.text


def test_serve_main_rejects_path_with_quote():
    with pytest.raises(SystemExit):
        server.serve_main(["--path", '/m"cp', "--", "true"])


def test_prm_honors_forwarded_headers(auth_gateway):
    url, _ = auth_gateway
    resp = httpx.get(
        _base(url) + "/.well-known/oauth-protected-resource/mcp",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "gw.example.org"},
        timeout=10,
    )
    assert resp.json()["resource"] == "https://gw.example.org/mcp"


def test_no_auth_fixture_still_open(gateway):
    # The default fixture has no token: a request without Authorization is 200.
    url, _ = gateway
    _, resp = _init(url)
    assert resp.status_code == 200


def test_sanitize_host():
    assert server._sanitize_host("gw.example.org:8443") == "gw.example.org:8443"
    # quote / CR / LF / space are stripped (header-injection guard)
    assert server._sanitize_host('evil"\r\n host') == "evilhost"


def test_authorized_constant_time_paths():
    # Build a handler instance is heavy; exercise the token compare via a
    # lightweight stand-in object carrying the attributes _authorized reads.
    class Fake:
        auth_token = "tok"
        oauth = None

        def __init__(self, hdr):
            self.headers = {"Authorization": hdr}

    Fake._authorized = server._Handler._authorized
    assert Fake("Bearer tok")._authorized() is True
    assert Fake("Bearer no")._authorized() is False
    assert Fake("")._authorized() is False
    Fake.auth_token = None
    assert Fake("")._authorized() is True


# --- embedded OAuth 2.1 Authorization Server ---

_REDIRECT = "http://127.0.0.1:5555/callback"


@contextlib.contextmanager
def _run(*, auth_token=None, oauth=None):
    """Start a gateway with the given auth config; yield (base_url, registry)."""
    httpd, registry = server.build_server(
        _BACKEND, host="127.0.0.1", port=0, auth_token=auth_token, oauth=oauth
    )
    host, port = httpd.server_address[0], httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://{host}:{port}", registry
    finally:
        httpd.shutdown()
        registry.shutdown_all()
        httpd.server_close()


def _provider(**kw):
    kw.setdefault("public_url", None)
    kw.setdefault("trusted_user_header", None)
    kw.setdefault("dev_user", "alice")
    return server._OAuthProvider(**kw)


@pytest.fixture()
def oauth_gateway():
    """A gateway with the embedded AS enabled and --dev-user=alice."""
    with _run(oauth=_provider()) as (base, registry):
        yield base, registry


def _register(base, redirect=_REDIRECT):
    return httpx.post(
        base + "/register",
        json={
            "client_name": "test",
            "redirect_uris": [redirect],
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none",
        },
        timeout=10,
    )


def _authorize(
    base,
    client_id,
    challenge,
    *,
    redirect=_REDIRECT,
    state="st-123",
    method="S256",
    response_type="code",
    headers=None,
    drop=None,
):
    params = {
        "client_id": client_id,
        "response_type": response_type,
        "redirect_uri": redirect,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": method,
        "resource": base + "/mcp",
    }
    for k in drop or []:
        params.pop(k, None)
    return httpx.get(
        base + "/authorize",
        params=params,
        headers=headers or {},
        follow_redirects=False,
        timeout=10,
    )


def _redirect_params(resp):
    return {
        k: v[0] for k, v in parse_qs(urlsplit(resp.headers["location"]).query).items()
    }


def _token(base, data):
    return httpx.post(base + "/token", data=data, timeout=10)


def _authed_mcp(base, token, mid=1):
    """An authenticated MCP call with the given bearer token.

    Uses ``initialize`` so a valid token gets 200 (and opens a session) while
    an invalid one is rejected by the auth gate (401) before session creation —
    exactly the status distinction these tests assert.
    """
    return httpx.post(
        base + "/mcp",
        content=json.dumps({"jsonrpc": "2.0", "id": mid, "method": "initialize"}),
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )


def _full_flow(base, redirect=_REDIRECT, headers=None):
    cid = _register(base, redirect).json()["client_id"]
    verifier, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge, redirect=redirect, headers=headers)
    assert az.status_code == 302, az.text
    code = _redirect_params(az)["code"]
    tok = _token(
        base,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect,
            "client_id": cid,
            "code_verifier": verifier,
        },
    )
    return cid, verifier, challenge, code, tok


# -- metadata / registration --


def test_pkce_s256_matches_client():
    # The server transform MUST equal what the client's generate_pkce produced.
    verifier, challenge = client_oauth.generate_pkce()
    assert server._pkce_s256_challenge(verifier) == challenge


def test_as_metadata(oauth_gateway):
    base, _ = oauth_gateway
    md = httpx.get(base + "/.well-known/oauth-authorization-server", timeout=10).json()
    assert md["issuer"].startswith("http://127.0.0.1:")
    assert md["authorization_endpoint"] == md["issuer"] + "/authorize"
    assert md["token_endpoint"] == md["issuer"] + "/token"
    assert md["registration_endpoint"] == md["issuer"] + "/register"
    assert md["response_types_supported"] == ["code"]
    assert md["code_challenge_methods_supported"] == ["S256"]
    assert md["token_endpoint_auth_methods_supported"] == ["none"]


def test_prm_has_authorization_servers_when_oauth(oauth_gateway):
    base, _ = oauth_gateway
    prm = httpx.get(
        base + "/.well-known/oauth-protected-resource/mcp", timeout=10
    ).json()
    assert prm["authorization_servers"] == [prm["resource"].rsplit("/mcp", 1)[0]]


def test_as_metadata_no_iss_flag_for_http_issuer(oauth_gateway):
    """RFC 9207 Sec. 2 requires an https iss; a loopback http issuer must NOT
    advertise iss support (it also never emits iss — see authorize tests)."""
    base, _ = oauth_gateway
    md = httpx.get(base + "/.well-known/oauth-authorization-server", timeout=10).json()
    assert "authorization_response_iss_parameter_supported" not in md


def test_https_issuer_advertises_and_emits_iss():
    """RFC 9207: an https issuer advertises iss support AND echoes iss on the
    authorization redirect (success path), so a multi-AS client can detect
    a mix-up attack."""
    issuer = "https://gw.example.org"
    with _run(oauth=_provider(public_url=issuer)) as (base, _):
        md = httpx.get(
            base + "/.well-known/oauth-authorization-server", timeout=10
        ).json()
        assert md["authorization_response_iss_parameter_supported"] is True
        cid = _register(base).json()["client_id"]
        _, challenge = client_oauth.generate_pkce()
        az = _authorize(base, cid, challenge)
        assert az.status_code == 302, az.text
        params = _redirect_params(az)
        assert params["iss"] == issuer
        assert "code" in params  # success response still carries the code


def test_https_issuer_emits_iss_on_error_redirect():
    """RFC 9207 Sec. 2: iss appears on error authorization responses too."""
    issuer = "https://gw.example.org"
    with _run(oauth=_provider(public_url=issuer)) as (base, _):
        cid = _register(base).json()["client_id"]
        _, challenge = client_oauth.generate_pkce()
        az = _authorize(base, cid, challenge, response_type="token")
        assert az.status_code == 302, az.text
        params = _redirect_params(az)
        assert params["error"] == "unsupported_response_type"
        assert params["iss"] == issuer


def test_register_response_is_no_store(oauth_gateway):
    """RFC 7591 Sec. 3.2.1: the registration response carries no-store."""
    base, _ = oauth_gateway
    r = _register(base)
    assert r.status_code == 201
    assert "no-store" in r.headers.get("cache-control", "")


def test_register_public_client(oauth_gateway):
    base, _ = oauth_gateway
    r = _register(base)
    assert r.status_code == 201
    body = r.json()
    assert isinstance(body["client_id"], str) and body["client_id"]
    assert "client_secret" not in body
    assert body["token_endpoint_auth_method"] == "none"


def test_register_rejects_non_loopback(oauth_gateway):
    base, _ = oauth_gateway
    r = _register(base, redirect="https://evil.example.com/callback")
    assert r.status_code == 400
    # RFC 7591 Sec. 3.2.2: an invalid redirect URI uses the dedicated error code.
    assert r.json()["error"] == "invalid_redirect_uri"


def test_register_missing_redirect_uris_is_client_metadata_error(oauth_gateway):
    """RFC 7591 Sec. 3.2.2: a missing/empty redirect_uris is a STRUCTURAL
    metadata error (invalid_client_metadata), not invalid_redirect_uri."""
    base, _ = oauth_gateway
    r = httpx.post(base + "/register", json={"client_name": "x"}, timeout=10)
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_client_metadata"
    r2 = httpx.post(base + "/register", json={"redirect_uris": []}, timeout=10)
    assert r2.status_code == 400
    assert r2.json()["error"] == "invalid_client_metadata"


def test_register_rejects_non_json(oauth_gateway):
    base, _ = oauth_gateway
    r = httpx.post(base + "/register", content="not json", timeout=10)
    assert r.status_code == 400


# -- full flow + RS --


def test_full_auth_code_flow_and_use_token(oauth_gateway):
    base, _ = oauth_gateway
    cid, verifier, challenge, code, tok = _full_flow(base)
    assert tok.status_code == 200, tok.text
    body = tok.json()
    assert body["token_type"] == "Bearer"
    assert isinstance(body["access_token"], str) and body["access_token"]
    assert body["expires_in"] > 0
    assert body["refresh_token"]
    assert tok.headers.get("cache-control") == "no-store"
    # use the issued token on an MCP request
    auth = {"Authorization": f"Bearer {body['access_token']}"}
    sid, _ = _init(base + "/mcp", headers=auth)
    r = httpx.post(
        base + "/mcp",
        content=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "echo", "params": {"x": 1}}
        ),
        headers={**auth, "Mcp-Session-Id": sid},
        timeout=10,
    )
    assert r.status_code == 200
    assert r.json()["result"]["echoed"] == {"x": 1}
    # without the token -> 401
    r2 = httpx.post(
        base + "/mcp",
        content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "echo"}),
        timeout=10,
    )
    assert r2.status_code == 401


def test_redirect_uri_port_agnostic(oauth_gateway):
    # RFC 8252: registered :5555, authorize with :6666 (same scheme/host/path) ok.
    base, _ = oauth_gateway
    cid = _register(base, "http://127.0.0.1:5555/callback").json()["client_id"]
    verifier, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge, redirect="http://127.0.0.1:6666/callback")
    assert az.status_code == 302


# -- authorize negatives --


def test_authorize_unknown_client_400_no_redirect(oauth_gateway):
    base, _ = oauth_gateway
    _, challenge = client_oauth.generate_pkce()
    az = _authorize(base, "nope", challenge)
    assert az.status_code == 400  # NOT a redirect (RFC 6749 4.1.2.1)


def test_authorize_bad_redirect_uri_400(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    _, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge, redirect="http://127.0.0.1:5555/evil")
    assert az.status_code == 400


def test_authorize_missing_code_challenge_redirects_error(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    az = _authorize(base, cid, "x", drop=["code_challenge"])
    assert az.status_code == 302
    p = _redirect_params(az)
    assert p["error"] == "invalid_request"
    assert p["state"] == "st-123"  # state echoed on error


def test_authorize_plain_method_rejected(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    _, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge, method="plain")
    assert az.status_code == 302
    assert _redirect_params(az)["error"] == "invalid_request"


def test_authorize_unsupported_response_type(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    _, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge, response_type="token")
    assert az.status_code == 302
    assert _redirect_params(az)["error"] == "unsupported_response_type"


def test_authorize_fail_closed_without_user():
    # No dev_user, no trusted header: a client-set X-Forwarded-User must NOT
    # authenticate -> access_denied (never mint a code for a spoofed user).
    with _run(oauth=_provider(dev_user=None)) as (base, _):
        cid = _register(base).json()["client_id"]
        _, challenge = client_oauth.generate_pkce()
        az = _authorize(base, cid, challenge, headers={"X-Forwarded-User": "attacker"})
        assert az.status_code == 302
        assert _redirect_params(az)["error"] == "access_denied"


def test_trusted_header_used_when_configured():
    with _run(
        oauth=_provider(dev_user=None, trusted_user_header="X-Forwarded-User")
    ) as (base, _):
        cid = _register(base).json()["client_id"]
        _, challenge = client_oauth.generate_pkce()
        az = _authorize(base, cid, challenge, headers={"X-Forwarded-User": "bob"})
        assert az.status_code == 302
        assert "code" in _redirect_params(az)


# -- token negatives --


def test_token_pkce_mismatch_invalid_grant(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    _, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge)
    code = _redirect_params(az)["code"]
    bad_verifier = "B" * 64
    r = _token(
        base,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": _REDIRECT,
            "client_id": cid,
            "code_verifier": bad_verifier,
        },
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


def test_token_code_replay_invalid_grant(oauth_gateway):
    base, _ = oauth_gateway
    cid, verifier, challenge, code, tok = _full_flow(base)
    assert tok.status_code == 200
    # replay the same code
    r = _token(
        base,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": _REDIRECT,
            "client_id": cid,
            "code_verifier": verifier,
        },
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


def test_token_redirect_uri_mismatch(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    verifier, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge)
    code = _redirect_params(az)["code"]
    r = _token(
        base,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://127.0.0.1:9999/callback",
            "client_id": cid,
            "code_verifier": verifier,
        },
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


def test_token_unsupported_grant(oauth_gateway):
    base, _ = oauth_gateway
    r = _token(base, {"grant_type": "password", "username": "x"})
    assert r.status_code == 400
    assert r.json()["error"] == "unsupported_grant_type"


def test_token_missing_grant(oauth_gateway):
    base, _ = oauth_gateway
    r = _token(base, {"foo": "bar"})
    assert r.status_code == 400


def test_refresh_rotates(oauth_gateway):
    base, _ = oauth_gateway
    cid, verifier, challenge, code, tok = _full_flow(base)
    rt = tok.json()["refresh_token"]
    r = _token(
        base, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid}
    )
    assert r.status_code == 200
    assert r.json()["access_token"]
    new_rt = r.json()["refresh_token"]
    assert new_rt and new_rt != rt
    # old refresh token is invalidated (rotation)
    again = _token(
        base, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid}
    )
    assert again.status_code == 400


def test_concurrent_token_single_use(oauth_gateway):
    base, _ = oauth_gateway
    cid = _register(base).json()["client_id"]
    verifier, challenge = client_oauth.generate_pkce()
    az = _authorize(base, cid, challenge)
    code = _redirect_params(az)["code"]
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _REDIRECT,
        "client_id": cid,
        "code_verifier": verifier,
    }
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda _: _token(base, data).status_code, range(8)))
    assert results.count(200) == 1
    assert results.count(400) == 7


def test_issued_token_expires():
    clock = [1000.0]
    prov = _provider(access_ttl=30, now=lambda: clock[0])
    with _run(oauth=prov) as (base, _):
        _, _, _, _, tok = _full_flow(base)
        at = tok.json()["access_token"]
        ok = httpx.post(
            base + "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            headers={"Authorization": f"Bearer {at}"},
            timeout=10,
        )
        assert ok.status_code == 200
        clock[0] += 100  # advance past TTL
        expired = httpx.post(
            base + "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "echo"}),
            headers={"Authorization": f"Bearer {at}"},
            timeout=10,
        )
        assert expired.status_code == 401


# -- coexistence / disabled --


def test_coexistence_static_and_oauth():
    with _run(auth_token="static-tok", oauth=_provider()) as (base, _):
        # static token authorizes
        r1 = httpx.post(
            base + "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            headers={"Authorization": "Bearer static-tok"},
            timeout=10,
        )
        assert r1.status_code == 200
        # issued token authorizes
        _, _, _, _, tok = _full_flow(base)
        at = tok.json()["access_token"]
        r2 = httpx.post(
            base + "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "initialize"}),
            headers={"Authorization": f"Bearer {at}"},
            timeout=10,
        )
        assert r2.status_code == 200
        # PRM advertises authorization_servers
        prm = httpx.get(
            base + "/.well-known/oauth-protected-resource/mcp", timeout=10
        ).json()
        assert "authorization_servers" in prm


def _mcp(base, msg, *, token=None, sid=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if sid:
        headers["Mcp-Session-Id"] = sid
    return httpx.post(
        base + "/mcp", content=json.dumps(msg), headers=headers, timeout=10
    )


def test_registry_owner_binding():
    # A session bound to a user is reachable only by that user.
    reg = server.SessionRegistry(_BACKEND)
    try:
        sid, _ = reg.create(owner="alice")
        assert reg.get(sid, "alice") is not None
        assert reg.get(sid, "bob") is None  # bound to alice
        assert reg.get(sid, None) is None  # a static/no-auth request
        assert reg.remove(sid, "bob") is None  # bob cannot tear it down
        assert reg.count == 1
        assert reg.remove(sid, "alice") is not None
        assert reg.count == 0
    finally:
        reg.shutdown_all()


def test_unbound_session_reachable_by_anyone():
    # owner=None (no-auth / static token) -> no per-user binding.
    reg = server.SessionRegistry(_BACKEND)
    try:
        sid, _ = reg.create()
        assert reg.get(sid, None) is not None
        assert reg.get(sid, "anyone") is not None
    finally:
        reg.shutdown_all()


def test_oauth_session_bound_to_owner():
    # End-to-end: a session opened by alice cannot be used or deleted by bob,
    # even though bob holds a valid token (a session id is a capability).
    prov = _provider(trusted_user_header="X-Forwarded-User", dev_user=None)
    with _run(oauth=prov) as (base, _):
        _, _, _, _, tok_a = _full_flow(base, headers={"X-Forwarded-User": "alice"})
        access_a = tok_a.json()["access_token"]
        _, _, _, _, tok_b = _full_flow(base, headers={"X-Forwarded-User": "bob"})
        access_b = tok_b.json()["access_token"]

        r = _mcp(
            base, {"jsonrpc": "2.0", "id": "i", "method": "initialize"}, token=access_a
        )
        assert r.status_code == 200
        sid = r.headers["mcp-session-id"]

        # alice uses her own session
        assert (
            _mcp(
                base,
                {"jsonrpc": "2.0", "id": 1, "method": "echo"},
                token=access_a,
                sid=sid,
            ).status_code
            == 200
        )
        # bob (valid token, different user) presenting alice's sid -> 404
        assert (
            _mcp(
                base,
                {"jsonrpc": "2.0", "id": 2, "method": "echo"},
                token=access_b,
                sid=sid,
            ).status_code
            == 404
        )
        # bob cannot DELETE alice's session either
        assert (
            httpx.request(
                "DELETE",
                base + "/mcp",
                headers={"Authorization": f"Bearer {access_b}", "Mcp-Session-Id": sid},
                timeout=10,
            ).status_code
            == 404
        )
        # alice's session survives bob's probing
        assert (
            _mcp(
                base,
                {"jsonrpc": "2.0", "id": 3, "method": "echo"},
                token=access_a,
                sid=sid,
            ).status_code
            == 200
        )
        # bob's token IS valid (distinct principal): he opens his own session,
        # which pins the 404s above to ownership, not an auth failure.
        rb = _mcp(
            base, {"jsonrpc": "2.0", "id": "ib", "method": "initialize"}, token=access_b
        )
        assert rb.status_code == 200
        assert rb.headers["mcp-session-id"] != sid


def test_oauth_sse_stream_bound_to_owner():
    # The GET SSE path is ownership-checked too: bob cannot open alice's stream.
    prov = _provider(trusted_user_header="X-Forwarded-User", dev_user=None)
    with _run(oauth=prov) as (base, _):
        _, _, _, _, tok_a = _full_flow(base, headers={"X-Forwarded-User": "alice"})
        access_a = tok_a.json()["access_token"]
        _, _, _, _, tok_b = _full_flow(base, headers={"X-Forwarded-User": "bob"})
        access_b = tok_b.json()["access_token"]
        r = _mcp(
            base, {"jsonrpc": "2.0", "id": "i", "method": "initialize"}, token=access_a
        )
        sid = r.headers["mcp-session-id"]
        # bob's GET with alice's sid -> 404 (binding), not a hung stream
        gr = httpx.get(
            base + "/mcp",
            headers={"Authorization": f"Bearer {access_b}", "Mcp-Session-Id": sid},
            timeout=10,
        )
        assert gr.status_code == 404
        # positive control: alice still owns the session
        assert (
            _mcp(
                base,
                {"jsonrpc": "2.0", "id": 1, "method": "echo"},
                token=access_a,
                sid=sid,
            ).status_code
            == 200
        )


def test_refreshed_token_keeps_session_ownership():
    # A rotated (refreshed) access token is the same principal and still owns
    # the session opened with the original token.
    prov = _provider(trusted_user_header="X-Forwarded-User", dev_user=None)
    with _run(oauth=prov) as (base, _):
        cid, _, _, _, tok = _full_flow(base, headers={"X-Forwarded-User": "alice"})
        access1 = tok.json()["access_token"]
        refresh = tok.json()["refresh_token"]
        r = _mcp(
            base, {"jsonrpc": "2.0", "id": "i", "method": "initialize"}, token=access1
        )
        sid = r.headers["mcp-session-id"]
        tok2 = _token(
            base,
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": cid,
            },
        )
        access2 = tok2.json()["access_token"]
        assert access2 and access2 != access1
        assert (
            _mcp(
                base,
                {"jsonrpc": "2.0", "id": 1, "method": "echo"},
                token=access2,
                sid=sid,
            ).status_code
            == 200
        )


def test_oauth_user_cannot_ride_static_session():
    # The fixed direction: on a static + OAuth gateway, a static-token session
    # is bound to the static principal — an OAuth user cannot ride or DELETE it.
    prov = _provider(trusted_user_header="X-Forwarded-User", dev_user=None)
    with _run(auth_token="static-tok", oauth=prov) as (base, _):
        r = _mcp(
            base,
            {"jsonrpc": "2.0", "id": "i", "method": "initialize"},
            token="static-tok",
        )
        assert r.status_code == 200
        sid = r.headers["mcp-session-id"]
        _, _, _, _, tok_a = _full_flow(base, headers={"X-Forwarded-User": "alice"})
        access_a = tok_a.json()["access_token"]
        assert (
            _mcp(
                base,
                {"jsonrpc": "2.0", "id": 1, "method": "echo"},
                token=access_a,
                sid=sid,
            ).status_code
            == 404
        )
        assert (
            httpx.request(
                "DELETE",
                base + "/mcp",
                headers={"Authorization": f"Bearer {access_a}", "Mcp-Session-Id": sid},
                timeout=10,
            ).status_code
            == 404
        )
        # the static session itself still works
        assert (
            _mcp(
                base,
                {"jsonrpc": "2.0", "id": 2, "method": "echo"},
                token="static-tok",
                sid=sid,
            ).status_code
            == 200
        )


def test_static_token_cannot_ride_oauth_session():
    # On a static + OAuth gateway, a valid static token is a different (null)
    # principal: it must not route into or DELETE an OAuth-owned session.
    prov = _provider(trusted_user_header="X-Forwarded-User", dev_user=None)
    with _run(auth_token="static-tok", oauth=prov) as (base, _):
        _, _, _, _, tok_a = _full_flow(base, headers={"X-Forwarded-User": "alice"})
        access_a = tok_a.json()["access_token"]
        r = _mcp(
            base, {"jsonrpc": "2.0", "id": "i", "method": "initialize"}, token=access_a
        )
        assert r.status_code == 200
        sid = r.headers["mcp-session-id"]
        # the static token authenticates but is not alice -> 404 on her session
        assert (
            _mcp(
                base,
                {"jsonrpc": "2.0", "id": 1, "method": "echo"},
                token="static-tok",
                sid=sid,
            ).status_code
            == 404
        )
        assert (
            httpx.request(
                "DELETE",
                base + "/mcp",
                headers={"Authorization": "Bearer static-tok", "Mcp-Session-Id": sid},
                timeout=10,
            ).status_code
            == 404
        )
        # alice's session survives
        assert (
            _mcp(
                base,
                {"jsonrpc": "2.0", "id": 2, "method": "echo"},
                token=access_a,
                sid=sid,
            ).status_code
            == 200
        )


def test_as_endpoints_404_when_disabled(gateway):
    url, _ = gateway
    base = _base(url)
    for p in ("/.well-known/oauth-authorization-server", "/authorize"):
        assert httpx.get(base + p, timeout=10).status_code == 404
    for p in ("/register", "/token"):
        assert httpx.post(base + p, content="{}", timeout=10).status_code == 404


# -- issuer pinning --


def test_public_url_pins_issuer():
    with _run(oauth=_provider(public_url="https://gw.example.org")) as (base, _):
        md = httpx.get(
            base + "/.well-known/oauth-authorization-server", timeout=10
        ).json()
        assert md["issuer"] == "https://gw.example.org"
        assert md["authorization_endpoint"] == "https://gw.example.org/authorize"
        prm = httpx.get(
            base + "/.well-known/oauth-protected-resource/mcp", timeout=10
        ).json()
        assert prm["authorization_servers"] == ["https://gw.example.org"]


# -- path-scoped issuer (#245): multiple --enable-oauth backends behind one host --

_PREFIXED = "https://gw.example.org/team-a"


def test_path_scoped_as_metadata_root_inserted():
    """A path-scoped issuer serves AS metadata at the RFC 8414 Sec. 3.1
    root-inserted location, advertising prefixed endpoints; the bare-origin
    location 404s so two backends never collide there."""
    with _run(oauth=_provider(public_url=_PREFIXED)) as (base, _):
        # Root-inserted well-known: /.well-known/oauth-authorization-server/team-a
        md = httpx.get(
            base + "/.well-known/oauth-authorization-server/team-a", timeout=10
        ).json()
        assert md["issuer"] == _PREFIXED
        assert md["authorization_endpoint"] == _PREFIXED + "/authorize"
        assert md["token_endpoint"] == _PREFIXED + "/token"
        assert md["registration_endpoint"] == _PREFIXED + "/register"
        # The bare-origin AS metadata path must NOT serve this backend.
        assert (
            httpx.get(
                base + "/.well-known/oauth-authorization-server", timeout=10
            ).status_code
            == 404
        )


def test_path_scoped_prm_root_inserted():
    """PRM is root-inserted with the full resource path (prefix + mcp_path),
    byte-symmetric with the client's _build_well_known_url."""
    with _run(oauth=_provider(public_url=_PREFIXED)) as (base, _):
        prm = httpx.get(
            base + "/.well-known/oauth-protected-resource/team-a/mcp", timeout=10
        ).json()
        assert prm["resource"] == _PREFIXED + "/mcp"
        assert prm["authorization_servers"] == [_PREFIXED]


def test_path_scoped_bare_as_endpoints_404():
    """With a prefix pinned, the bare-origin AS endpoints 404 (isolation)."""
    with _run(oauth=_provider(public_url=_PREFIXED)) as (base, _):
        assert httpx.get(base + "/authorize", timeout=10).status_code == 404
        assert (
            httpx.post(base + "/register", content="{}", timeout=10).status_code == 404
        )
        assert httpx.post(base + "/token", content="x=1", timeout=10).status_code == 404
        # The MCP endpoint also lives under the prefix now.
        assert httpx.post(base + "/mcp", content="{}", timeout=10).status_code == 404


def test_path_scoped_full_flow():
    """End-to-end under a path prefix: DCR -> PKCE authorize -> token -> MCP."""
    prefix = "/team-a"
    with _run(oauth=_provider(public_url=_PREFIXED)) as (base, _):
        # DCR under the prefix.
        cid = httpx.post(
            base + prefix + "/register",
            json={
                "client_name": "test",
                "redirect_uris": [_REDIRECT],
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "none",
            },
            timeout=10,
        ).json()["client_id"]
        verifier, challenge = client_oauth.generate_pkce()
        az = httpx.get(
            base + prefix + "/authorize",
            params={
                "client_id": cid,
                "response_type": "code",
                "redirect_uri": _REDIRECT,
                "state": "st-1",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": _PREFIXED + "/mcp",
            },
            follow_redirects=False,
            timeout=10,
        )
        assert az.status_code == 302, az.text
        code = _redirect_params(az)["code"]
        tok = httpx.post(
            base + prefix + "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _REDIRECT,
                "client_id": cid,
                "code_verifier": verifier,
            },
            timeout=10,
        ).json()
        access = tok["access_token"]
        # The issued token authorizes a real MCP call at the prefixed path.
        r = httpx.post(
            base + prefix + "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            headers={"Authorization": f"Bearer {access}"},
            timeout=10,
        )
        assert r.status_code == 200
        # An unauthenticated prefixed MCP call is challenged with the
        # root-inserted PRM hint.
        chal = httpx.post(
            base + prefix + "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "echo"}),
            timeout=10,
        )
        assert chal.status_code == 401
        assert (
            "/.well-known/oauth-protected-resource/team-a/mcp"
            in chal.headers["WWW-Authenticate"]
        )


def test_two_path_scoped_backends_do_not_collide():
    """Two prefixes route to disjoint AS-metadata / endpoint paths."""
    a = "https://gw.example.org/team-a"
    b = "https://gw.example.org/team-b"
    with _run(oauth=_provider(public_url=a)) as (base_a, _):
        with _run(oauth=_provider(public_url=b)) as (base_b, _):
            # Each backend answers only at its own root-inserted metadata path.
            assert (
                httpx.get(
                    base_a + "/.well-known/oauth-authorization-server/team-a",
                    timeout=10,
                ).json()["issuer"]
                == a
            )
            assert (
                httpx.get(
                    base_a + "/.well-known/oauth-authorization-server/team-b",
                    timeout=10,
                ).status_code
                == 404
            )
            assert (
                httpx.get(
                    base_b + "/.well-known/oauth-authorization-server/team-b",
                    timeout=10,
                ).json()["issuer"]
                == b
            )
            assert (
                httpx.get(
                    base_b + "/.well-known/oauth-authorization-server/team-a",
                    timeout=10,
                ).status_code
                == 404
            )


def test_normalize_public_url():
    # A bare origin is unchanged (legacy behavior).
    assert (
        server._normalize_public_url("https://gw.example.org")
        == "https://gw.example.org"
    )
    assert (
        server._normalize_public_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
    )
    # A path is RETAINED as the issuer prefix (#245), trailing slash stripped.
    assert (
        server._normalize_public_url("https://gw.example.org/team-a")
        == "https://gw.example.org/team-a"
    )
    assert (
        server._normalize_public_url("https://gw.example.org/team-a/")
        == "https://gw.example.org/team-a"
    )
    assert (
        server._normalize_public_url("https://gw.example.org/a/b")
        == "https://gw.example.org/a/b"
    )
    # A bare host with only a trailing slash collapses to the bare origin.
    assert (
        server._normalize_public_url("https://gw.example.org/")
        == "https://gw.example.org"
    )
    # canonicalization: lowercase host, drop explicit default port, keep path
    assert (
        server._normalize_public_url("https://EXAMPLE.com:443/x")
        == "https://example.com/x"
    )
    assert server._normalize_public_url("http://LOCALHOST:80") == "http://localhost"
    for bad in (
        "ftp://h",
        "https://",
        'https://h"x',
        "https://user@h",
        "http://gw.example.org",  # non-loopback http is rejected
        "https://gw.example.org/a?q=1",  # query forbidden in an issuer
        "https://gw.example.org/a#f",  # fragment forbidden in an issuer
        "https://gw.example.org/../admin",  # traversal segment rejected
        "https://gw.example.org/a/../b",  # interior traversal rejected
        "https://gw.example.org/a//b",  # empty segment rejected
        "https://gw.example.org/a/./b",
    ):  # "." segment rejected
        with pytest.raises(ValueError):
            server._normalize_public_url(bad)


# -- CLI flag validation (error paths return before serve() blocks) --


def test_serve_main_dev_user_requires_oauth():
    with pytest.raises(SystemExit):
        server.serve_main(["--dev-user", "x", "--", "true"])


def test_serve_main_bad_public_url():
    with pytest.raises(SystemExit):
        server.serve_main(
            [
                "--enable-oauth",
                "--public-url",
                "ftp://x",
                "--dev-user",
                "a",
                "--",
                "true",
            ]
        )


def test_serve_main_bad_trusted_header():
    with pytest.raises(SystemExit):
        server.serve_main(
            ["--enable-oauth", "--trusted-user-header", "bad header", "--", "true"]
        )


def test_serve_main_allow_redirect_uri_requires_oauth():
    with pytest.raises(SystemExit):
        server.serve_main(["--allow-redirect-uri", _ALLOWED_HTTPS, "--", "true"])


def test_serve_main_bad_allow_redirect_uri():
    with pytest.raises(SystemExit):
        server.serve_main(
            [
                "--enable-oauth",
                "--dev-user",
                "a",
                "--allow-redirect-uri",
                "http://not-https.example/cb",
                "--",
                "true",
            ]
        )


# -- real-client interop: drive mcp_stdio.oauth.ensure_token end to end --


def test_real_client_ensure_token(monkeypatch, tmp_path):
    # Point the client token store at a temp dir (no touching real ~/.config).
    from mcp_stdio import token_store

    monkeypatch.setattr(token_store, "_STORE_DIR", tmp_path)
    monkeypatch.setattr(token_store, "_STORE_FILE", tmp_path / "tokens.json")
    monkeypatch.setattr(token_store, "_LEGACY_STORE_DIR", tmp_path / "legacy")
    monkeypatch.setattr(
        token_store, "_LEGACY_STORE_FILE", tmp_path / "legacy" / "tokens.json"
    )

    with _run(oauth=_provider(dev_user="alice")) as (base, _):
        # The client opens a browser at auth_url then waits for its loopback
        # callback. Simulate the browser in a BACKGROUND thread (a synchronous
        # GET would deadlock: the callback server's serve() thread starts only
        # AFTER webbrowser.open returns).
        def fake_open(auth_url):
            def drive():
                r = httpx.get(auth_url, follow_redirects=False, timeout=10)
                if r.status_code == 302:
                    httpx.get(r.headers["location"], timeout=10)

            threading.Thread(target=drive, daemon=True).start()

        monkeypatch.setattr(client_oauth.webbrowser, "open", fake_open)

        with httpx.Client(timeout=10) as client:
            td = client_oauth.ensure_token(base + "/mcp", client, timeout=15)
        assert td.access_token
        # the obtained token authorizes a real MCP call
        r = httpx.post(
            base + "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            headers={"Authorization": f"Bearer {td.access_token}"},
            timeout=10,
        )
        assert r.status_code == 200


# --- adversarial-review fixes ---


def test_store_cap_is_a_hard_bound(monkeypatch):
    # GC frees only expired entries; the cap must still bound live tokens.
    monkeypatch.setattr(server, "_STORE_CAP", 5)
    prov = _provider()
    for i in range(30):
        prov._issue(f"u{i}", "c", "", None)
    assert len(prov._access) <= 5
    assert len(prov._refresh) <= 5


def test_client_cap_recycles_not_bricks(monkeypatch):
    # /register must never permanently lock out: at the cap the oldest client
    # is recycled rather than rejected.
    monkeypatch.setattr(server, "_CLIENT_CAP", 3)
    prov = _provider()
    last = None
    for i in range(8):
        status, body = prov.register(
            json.dumps(
                {"redirect_uris": [f"http://127.0.0.1:{1000 + i}/callback"]}
            ).encode()
        )
        assert status == 201, body
        last = body["client_id"]
    assert len(prov._clients) <= 3
    assert last in prov._clients  # newest registration survives


def test_redirect_key_rejects_query_userinfo_fragment():
    assert server._redirect_key("http://127.0.0.1:5/cb") == ("http", "127.0.0.1", "/cb")
    assert server._redirect_key("http://127.0.0.1:5/cb?next=x") is None
    assert server._redirect_key("http://u:p@127.0.0.1:5/cb") is None
    assert server._redirect_key("http://127.0.0.1:5/cb#frag") is None
    assert server._redirect_key("https://127.0.0.1:5/cb") is None
    assert server._redirect_key("http://evil.example.com/cb") is None


def test_register_rejects_query_bearing_redirect(oauth_gateway):
    base, _ = oauth_gateway
    r = _register(base, redirect="http://127.0.0.1:5555/callback?next=x")
    assert r.status_code == 400
    # RFC 7591 Sec. 3.2.2: an invalid redirect URI uses the dedicated error code.
    assert r.json()["error"] == "invalid_redirect_uri"


# -- --allow-redirect-uri: exact-match remote HTTPS callback --

_ALLOWED_HTTPS = "https://claude.example/api/mcp/auth_callback"


def test_validate_allowed_redirect_uri_accepts_https_rejects_bad():
    assert server._validate_allowed_redirect_uri(_ALLOWED_HTTPS) == _ALLOWED_HTTPS
    for bad in (
        "http://claude.example/api/mcp/auth_callback",  # not https
        "https://u:p@claude.example/cb",  # userinfo
        "https://claude.example/cb#frag",  # fragment
        "https://claude.example/cb?next=x",  # query (see test below for why)
        "https:///cb",  # missing host
        "https://claude.example/cb\r\nX-Injected: 1",  # CR/LF
        "https://[::1/cb",  # malformed IPv6 host -> urlsplit itself raises
    ):
        with pytest.raises(ValueError, match=re.escape(repr(bad))):
            server._validate_allowed_redirect_uri(bad)


def test_validate_allowed_redirect_uri_rejects_query_to_prevent_double_question_mark():
    """A query-bearing allowlisted redirect_uri would make authorize()'s
    `redirect_uri + "?" + urlencode(query)` produce a malformed double-"?"
    Location, silently swallowing `code` into the tail of the existing
    query's last value instead of its own parameter -- the same failure mode
    _redirect_key() already guards against on the loopback path."""
    with pytest.raises(ValueError):
        server._validate_allowed_redirect_uri("https://claude.example/cb?evil=1")


def test_match_key_exact_is_independent_of_loopback():
    allowed = frozenset({_ALLOWED_HTTPS})
    # loopback still resolves through _redirect_key, unaffected by the allowlist
    assert server._match_key("http://127.0.0.1:5/cb", allowed) == (
        "loopback",
        "http",
        "127.0.0.1",
        "/cb",
    )
    # the exact allowlisted URI matches
    assert server._match_key(_ALLOWED_HTTPS, allowed) == ("exact", _ALLOWED_HTTPS)
    # a non-allowlisted https URL does not, even though it "looks" similar
    assert server._match_key("https://claude.example/other", allowed) is None
    assert (
        server._match_key(
            "https://claude.example.evil.com/api/mcp/auth_callback", allowed
        )
        is None
    )
    assert server._match_key(_ALLOWED_HTTPS + ":443", allowed) is None
    assert server._match_key(_ALLOWED_HTTPS + "/", allowed) is None


def test_register_accepts_allowlisted_https_redirect():
    with _run(oauth=_provider(allowed_redirect_uris=frozenset({_ALLOWED_HTTPS}))) as (
        base,
        _,
    ):
        r = _register(base, redirect=_ALLOWED_HTTPS)
        assert r.status_code == 201, r.text


def test_register_still_rejects_non_allowlisted_https_redirect():
    with _run(oauth=_provider(allowed_redirect_uris=frozenset({_ALLOWED_HTTPS}))) as (
        base,
        _,
    ):
        r = _register(base, redirect="https://evil.example.com/callback")
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_redirect_uri"


def test_register_logs_rejected_redirect_uri(capsys):
    """#286: a rejected DCR redirect_uri is logged so an operator can see exactly
    what to allowlist -- the wire response is only an opaque 400."""
    prov = _provider(allowed_redirect_uris=frozenset({_ALLOWED_HTTPS}))
    rejected = "https://evil.example.com/callback"
    status, body = prov.register(json.dumps({"redirect_uris": [rejected]}).encode())
    assert status == 400
    assert body["error"] == "invalid_redirect_uri"
    err = capsys.readouterr().err
    assert "rejected DCR redirect_uri" in err
    assert rejected in err


def test_rejected_redirect_uri_log_is_crlf_safe(capsys):
    """#286: a CR/LF-bearing redirect_uri is escaped (repr), so it cannot forge a
    second log line (log injection)."""
    prov = _provider()
    status, _ = prov.register(
        json.dumps(
            {"redirect_uris": ["https://evil.example/a\r\nINJECTED line"]}
        ).encode()
    )
    assert status == 400
    err = capsys.readouterr().err
    injected_lines = [ln for ln in err.splitlines() if "INJECTED" in ln]
    # The raw newline is escaped, so INJECTED stays on the warning line rather
    # than starting a forged line of its own.
    assert injected_lines
    assert all("rejected DCR redirect_uri" in ln for ln in injected_lines)


def test_authorize_logs_rejected_redirect_uri(capsys):
    """#286: the /authorize path also logs a rejected redirect_uri (registered a
    client, then authorized with a different, non-allowlisted redirect_uri)."""
    prov = _provider()
    status, reg = prov.register(json.dumps({"redirect_uris": [_REDIRECT]}).encode())
    assert status == 201
    capsys.readouterr()  # drop registration output
    mismatched = "https://evil.example.com/callback"
    out = prov.authorize(
        {
            "client_id": reg["client_id"],
            "response_type": "code",
            "redirect_uri": mismatched,
            "code_challenge": "x",
            "code_challenge_method": "S256",
        },
        "alice",
        "https://gw.example",
    )
    assert out["kind"] == "bad_request"
    err = capsys.readouterr().err
    assert "rejected authorize redirect_uri" in err
    assert mismatched in err


def test_authorize_and_token_exchange_succeed_for_allowlisted_https_redirect():
    with _run(oauth=_provider(allowed_redirect_uris=frozenset({_ALLOWED_HTTPS}))) as (
        base,
        _,
    ):
        cid, verifier, challenge, code, tok = _full_flow(base, redirect=_ALLOWED_HTTPS)
        assert tok.status_code == 200, tok.text
        assert tok.json()["access_token"]


def test_authorize_rejects_lookalike_of_allowlisted_https_redirect():
    with _run(oauth=_provider(allowed_redirect_uris=frozenset({_ALLOWED_HTTPS}))) as (
        base,
        _,
    ):
        cid = _register(base, redirect=_ALLOWED_HTTPS).json()["client_id"]
        _, challenge = client_oauth.generate_pkce()
        for lookalike in (
            "https://claude.example.evil.com/api/mcp/auth_callback",  # host lookalike
            _ALLOWED_HTTPS + ":443",  # explicit default port, not byte-identical
            _ALLOWED_HTTPS + "/",  # trailing slash
            _ALLOWED_HTTPS.replace("https://", "http://"),  # scheme downgrade
        ):
            az = _authorize(base, cid, challenge, redirect=lookalike)
            assert az.status_code == 400, f"{lookalike!r} unexpectedly accepted"


def test_refresh_wrong_client_id_preserves_token(oauth_gateway):
    base, _ = oauth_gateway
    cid, _, _, _, tok = _full_flow(base)
    rt = tok.json()["refresh_token"]
    # a wrong client_id must be rejected WITHOUT destroying the valid token
    bad = _token(
        base, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": "wrong"}
    )
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant"
    good = _token(
        base, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid}
    )
    assert good.status_code == 200


def test_token_missing_grant_is_invalid_request(oauth_gateway):
    base, _ = oauth_gateway
    r = _token(base, {"foo": "bar"})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_request"


def test_401_hint_uses_pinned_issuer():
    with _run(oauth=_provider(public_url="https://gw.example.org")) as (base, _):
        r = httpx.post(
            base + "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "echo"}),
            timeout=10,
        )
        assert r.status_code == 401
        assert (
            'resource_metadata="https://gw.example.org/.well-known/'
            'oauth-protected-resource/mcp"'
        ) in r.headers["www-authenticate"]


def test_redact_query():
    out = server._redact_query('"GET /authorize?state=SECRET&x=1 HTTP/1.1" 302 -')
    assert out == '"GET /authorize?<redacted> HTTP/1.1" 302 -'
    assert "SECRET" not in out
    # absolute-form request target (RFC 7230, e.g. via a forwarding proxy) too
    out2 = server._redact_query(
        '"GET http://gw.example.org/authorize?state=SECRET&code=ABC HTTP/1.1" 404 -'
    )
    assert out2 == '"GET http://gw.example.org/authorize?<redacted> HTTP/1.1" 404 -'
    assert "SECRET" not in out2 and "ABC" not in out2
    # a query-less line is unchanged
    assert (
        server._redact_query('"POST /mcp HTTP/1.1" 200 -')
        == '"POST /mcp HTTP/1.1" 200 -'
    )


def test_concurrent_refresh_single_use(oauth_gateway):
    # The same refresh token submitted concurrently must rotate exactly once.
    base, _ = oauth_gateway
    cid, _, _, _, tok = _full_flow(base)
    rt = tok.json()["refresh_token"]
    data = {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid}
    with ThreadPoolExecutor(max_workers=8) as ex:
        codes = list(ex.map(lambda _: _token(base, data).status_code, range(8)))
    assert codes.count(200) == 1
    assert codes.count(400) == 7


def test_refresh_token_expires():
    clock = [1000.0]
    prov = _provider(refresh_ttl=50, now=lambda: clock[0])
    with _run(oauth=prov) as (base, _):
        cid, _, _, _, tok = _full_flow(base)
        rt = tok.json()["refresh_token"]
        clock[0] += 100  # advance past refresh_ttl
        r = _token(
            base, {"grant_type": "refresh_token", "refresh_token": rt, "client_id": cid}
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"


# -- RFC 6750 invalid_token challenge (audit fix A) --


def test_invalid_token_challenge_has_error(oauth_gateway):
    """RFC 6750 Sec. 3.1: a presented-but-invalid bearer token yields
    error="invalid_token" in the challenge."""
    base, _ = oauth_gateway
    r = _authed_mcp(base, "bogus-token")
    assert r.status_code == 401
    wa = r.headers.get("www-authenticate", "")
    assert 'error="invalid_token"' in wa
    assert "resource_metadata=" in wa


def test_no_token_challenge_omits_error(oauth_gateway):
    """RFC 6750 Sec. 3: with NO token presented, the error attribute is omitted
    (the bare challenge is how the client learns to authenticate)."""
    base, _ = oauth_gateway
    r = _post(base + "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "echo"})
    assert r.status_code == 401
    wa = r.headers.get("www-authenticate", "")
    assert "error=" not in wa
    assert "resource_metadata=" in wa


# -- RFC 8707 / MCP audience binding (audit fix H) --


def test_validate_access_token_audience():
    """A token minted for resource A is rejected when guarding resource B."""
    prov = _provider()
    _, body = prov._issue("u", "c", "", "https://api.example.com/mcp", family="f")
    token = body["access_token"]
    assert prov.validate_access_token(token, "https://api.example.com/mcp") is True
    # trailing-slash difference tolerated
    assert prov.validate_access_token(token, "https://api.example.com/mcp/") is True
    # a different audience is rejected even though the token is live
    assert prov.validate_access_token(token, "https://other.example.com/mcp") is False
    # no expected resource supplied -> lenient (back-compat)
    assert prov.validate_access_token(token, None) is True


def test_validate_access_token_no_audience_binding():
    """A token with no resource binding is accepted for any resource."""
    prov = _provider()
    _, body = prov._issue("u", "c", "", None, family="f")
    token = body["access_token"]
    assert prov.validate_access_token(token, "https://api.example.com/mcp") is True


def test_mcp_call_rejects_token_for_other_audience():
    """End-to-end: a token bound to a different resource cannot call this MCP."""
    with _run(oauth=_provider()) as (base, _):
        cid = _register(base).json()["client_id"]
        verifier, challenge = client_oauth.generate_pkce()
        # Authorize with a resource that is NOT this gateway's MCP endpoint.
        az = httpx.get(
            base + "/authorize",
            params={
                "client_id": cid,
                "response_type": "code",
                "redirect_uri": _REDIRECT,
                "state": "s",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": "https://other.example.com/mcp",
            },
            follow_redirects=False,
            timeout=10,
        )
        code = _redirect_params(az)["code"]
        tok = _token(
            base,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _REDIRECT,
                "client_id": cid,
                "code_verifier": verifier,
            },
        )
        access = tok.json()["access_token"]
        # The token is live but bound to other.example.com -> this RS rejects it.
        assert _authed_mcp(base, access).status_code == 401


# -- authorization-code replay revocation (audit fix F, RFC 6749 Sec. 4.1.2) --


def test_auth_code_replay_revokes_family():
    clock = [1000.0]
    prov = _provider(now=lambda: clock[0])
    with _run(oauth=prov) as (base, _):
        cid, verifier, challenge, code, tok = _full_flow(base)
        assert tok.status_code == 200
        access = tok.json()["access_token"]
        assert _authed_mcp(base, access).status_code == 200
        # Past the reuse grace window, replaying the code is a theft signal.
        clock[0] += _grace() + 5
        replay = _token(
            base,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _REDIRECT,
                "client_id": cid,
                "code_verifier": verifier,
            },
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"
        assert "revoked" in replay.json()["error_description"]
        # The previously-issued token is now revoked.
        assert _authed_mcp(base, access).status_code == 401


# -- refresh-token reuse revocation (audit fix G, RFC 9700 Sec. 4.14.2) --


def test_refresh_reuse_revokes_family():
    clock = [1000.0]
    prov = _provider(now=lambda: clock[0])
    with _run(oauth=prov) as (base, _):
        cid, _, _, _, tok = _full_flow(base)
        rt0 = tok.json()["refresh_token"]
        # Rotate rt0 -> rt1.
        r1 = _token(
            base,
            {"grant_type": "refresh_token", "refresh_token": rt0, "client_id": cid},
        )
        assert r1.status_code == 200
        access1 = r1.json()["access_token"]
        rt1 = r1.json()["refresh_token"]
        assert _authed_mcp(base, access1).status_code == 200
        # Within the grace window, reusing rt0 is denied but does NOT revoke.
        benign = _token(
            base,
            {"grant_type": "refresh_token", "refresh_token": rt0, "client_id": cid},
        )
        assert benign.status_code == 400
        assert benign.json()["error_description"] == "refresh_token already rotated"
        assert _authed_mcp(base, access1).status_code == 200  # survives
        # Past the grace window, reusing rt0 is theft -> revoke the whole family.
        clock[0] += _grace() + 5
        theft = _token(
            base,
            {"grant_type": "refresh_token", "refresh_token": rt0, "client_id": cid},
        )
        assert theft.status_code == 400
        assert "reuse detected" in theft.json()["error_description"]
        # access1 and rt1 (same family) are now revoked.
        assert _authed_mcp(base, access1).status_code == 401
        r3 = _token(
            base,
            {"grant_type": "refresh_token", "refresh_token": rt1, "client_id": cid},
        )
        assert r3.status_code == 400


def _grace():
    return server._REUSE_GRACE_SECS


# --- --token-store: AS state persistence across restarts (#277) ---
#
# Rationale: every serve restart (deploy, config change) previously
# invalidated ALL issued tokens; hosted remote-connector clients that do not
# re-authorize on 401/invalid_grant were left silently dead until a manual
# reconnect. These tests drive the provider directly (no HTTP) and simulate a
# restart by constructing a second provider over the same store file.


def _direct_flow(prov, *, resource=None, redirect=_REDIRECT):
    """register -> authorize -> token directly against the provider."""
    status, reg = prov.register(json.dumps({"redirect_uris": [redirect]}).encode())
    assert status == 201, reg
    cid = reg["client_id"]
    verifier, challenge = client_oauth.generate_pkce()
    params = {
        "client_id": cid,
        "response_type": "code",
        "redirect_uri": redirect,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if resource is not None:
        params["resource"] = resource
    out = prov.authorize(params, "alice", "https://gw.example")
    assert out["kind"] == "redirect", out
    code = parse_qs(urlsplit(out["location"]).query)["code"][0]
    status, tok = prov.token(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect,
            "client_id": cid,
            "code_verifier": verifier,
        }
    )
    assert status == 200, tok
    return cid, tok


def test_token_store_access_token_survives_restart(tmp_path):
    path = tmp_path / "as-state.json"
    p1 = _provider(store_path=path)
    _, tok = _direct_flow(p1)
    p2 = _provider(store_path=path)  # simulated restart
    assert p2.validate_access_token(tok["access_token"]) is True
    assert p2.user_for_token(tok["access_token"]) == "alice"


def test_token_store_refresh_and_client_survive_restart(tmp_path):
    path = tmp_path / "as-state.json"
    p1 = _provider(store_path=path)
    cid, tok = _direct_flow(p1)
    p2 = _provider(store_path=path)
    status, body = p2.token(
        {
            "grant_type": "refresh_token",
            "refresh_token": tok["refresh_token"],
            "client_id": cid,
        }
    )
    assert status == 200, body
    assert p2.validate_access_token(body["access_token"]) is True
    # The DCR registration also survived: the same client_id can authorize
    # again without a fresh POST /register.
    _, challenge = client_oauth.generate_pkce()
    out = p2.authorize(
        {
            "client_id": cid,
            "response_type": "code",
            "redirect_uri": _REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        "alice",
        "https://gw.example",
    )
    assert out["kind"] == "redirect" and "code=" in out["location"]


def test_token_store_resource_binding_survives_restart(tmp_path):
    path = tmp_path / "as-state.json"
    p1 = _provider(store_path=path)
    _, tok = _direct_flow(p1, resource="https://gw.example/mcp")
    p2 = _provider(store_path=path)
    access = tok["access_token"]
    assert p2.validate_access_token(access, "https://gw.example/mcp") is True
    # RFC 8707 audience binding is not laundered away by the round-trip.
    assert p2.validate_access_token(access, "https://other.example/mcp") is False


def test_token_store_refresh_reuse_detected_across_restart(tmp_path):
    # The rotation tombstone survives: replaying the pre-restart refresh
    # token after the grace window revokes the family in the NEW process.
    clock = [1000.0]
    path = tmp_path / "as-state.json"
    p1 = _provider(store_path=path, now=lambda: clock[0])
    cid, tok = _direct_flow(p1)
    rt0 = tok["refresh_token"]
    status, r1 = p1.token(
        {
            "grant_type": "refresh_token",
            "refresh_token": rt0,
            "client_id": cid,
        }
    )
    assert status == 200
    clock[0] += _grace() + 5
    p2 = _provider(store_path=path, now=lambda: clock[0])
    status, theft = p2.token(
        {
            "grant_type": "refresh_token",
            "refresh_token": rt0,
            "client_id": cid,
        }
    )
    assert status == 400
    assert "reuse detected" in theft["error_description"]
    # The family minted by the rotation is revoked in p2 as well.
    assert p2.validate_access_token(r1["access_token"]) is False
    status, _ = p2.token(
        {
            "grant_type": "refresh_token",
            "refresh_token": r1["refresh_token"],
            "client_id": cid,
        }
    )
    assert status == 400


def test_token_store_consumed_code_not_resurrected_by_restart(tmp_path):
    # Single-use survives: an authorization code spent before the restart
    # stays spent, and its replay past the grace window revokes the family.
    clock = [1000.0]
    path = tmp_path / "as-state.json"
    p1 = _provider(store_path=path, now=lambda: clock[0])
    status, reg = p1.register(json.dumps({"redirect_uris": [_REDIRECT]}).encode())
    cid = reg["client_id"]
    verifier, challenge = client_oauth.generate_pkce()
    out = p1.authorize(
        {
            "client_id": cid,
            "response_type": "code",
            "redirect_uri": _REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        "alice",
        "https://gw.example",
    )
    code = parse_qs(urlsplit(out["location"]).query)["code"][0]
    exchange = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _REDIRECT,
        "client_id": cid,
        "code_verifier": verifier,
    }
    status, tok = p1.token(exchange)
    assert status == 200
    clock[0] += _grace() + 5
    p2 = _provider(store_path=path, now=lambda: clock[0])
    status, replay = p2.token(exchange)
    assert status == 400
    assert "already used" in replay["error_description"]
    assert p2.validate_access_token(tok["access_token"]) is False


def test_token_store_expired_entries_dropped_on_load(tmp_path):
    clock = [1000.0]
    path = tmp_path / "as-state.json"
    p1 = _provider(store_path=path, now=lambda: clock[0], access_ttl=60.0)
    _, tok = _direct_flow(p1)
    clock[0] += 120  # access expired; refresh (30 days) still live
    p2 = _provider(store_path=path, now=lambda: clock[0])
    assert p2.validate_access_token(tok["access_token"]) is False
    assert tok["access_token"] not in p2._access  # dropped at load, not lazily
    assert tok["refresh_token"] in p2._refresh


def test_token_store_corrupt_file_starts_empty_then_replaced(tmp_path, capsys):
    path = tmp_path / "as-state.json"
    path.write_text("{not json", encoding="utf-8")
    p = _provider(store_path=path)
    assert p._access == {}
    assert "unreadable or corrupt" in capsys.readouterr().err
    # The next issuance replaces the corrupt file with a valid store.
    _direct_flow(p)
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 1


def test_token_store_unsupported_version_starts_empty(tmp_path, capsys):
    path = tmp_path / "as-state.json"
    path.write_text(json.dumps({"version": 99, "access": {"t": {}}}), encoding="utf-8")
    p = _provider(store_path=path)
    assert p._access == {}
    assert "unsupported version" in capsys.readouterr().err


def test_token_store_malformed_entries_dropped(tmp_path, capsys):
    good = {
        "user": "alice",
        "client_id": "c",
        "scope": "",
        "resource": None,
        "family": None,
        "expires_at": 4102444800.0,
    }
    path = tmp_path / "as-state.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "clients": {"cid": {"redirect_uris": "not-a-list", "created_at": 1.0}},
                "access": {
                    "good": good,
                    "non-str-user": {**good, "user": 42},
                    "bool-expiry": {**good, "expires_at": True},
                    "inf-expiry": {**good, "expires_at": float("inf")},
                    "not-a-dict": "x",
                },
                "refresh": {"": good},  # empty key
                "codes": "not-a-dict",  # whole store malformed
            }
        ),
        encoding="utf-8",
    )
    p = _provider(store_path=path)
    assert set(p._access) == {"good"}
    assert p._clients == {}
    assert p._refresh == {}
    assert p._codes == {}
    assert "dropped" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_token_store_file_created_0600(tmp_path):
    path = tmp_path / "as-state.json"
    p = _provider(store_path=path)
    _direct_flow(p)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_token_store_persist_failure_soft_fails_and_warns_once(
    tmp_path, capsys, monkeypatch
):
    path = tmp_path / "as-state.json"
    p = _provider(store_path=path)

    def boom(_path, _data):
        raise OSError("disk full")

    monkeypatch.setattr(server, "_atomic_write_json_file", boom)
    _, tok = _direct_flow(p)  # issuance still succeeds (availability first)
    assert p.validate_access_token(tok["access_token"]) is True
    _direct_flow(p)  # more mutations: still no second warning
    assert capsys.readouterr().err.count("could not persist OAuth state") == 1


def test_token_store_none_never_writes(monkeypatch):
    calls = []
    monkeypatch.setattr(server, "_atomic_write_json_file", lambda *a: calls.append(a))
    p = _provider()  # no store_path: pre-existing in-memory-only behavior
    _direct_flow(p)
    assert calls == []


def test_serve_main_token_store_requires_oauth():
    with pytest.raises(SystemExit):
        server.serve_main(["--token-store", "/tmp/x.json", "--", "true"])


def test_serve_main_token_store_empty_path_rejected():
    with pytest.raises(SystemExit):
        server.serve_main(
            [
                "--enable-oauth",
                "--dev-user",
                "a",
                "--token-store",
                "  ",
                "--",
                "true",
            ]
        )


def test_token_store_removed_allowlist_entry_stops_matching_after_restart(tmp_path):
    # redirect_keys are recomputed on load against the CURRENT allowlist: a
    # client registered for an https redirect the operator later removes from
    # --allow-redirect-uri is dropped, not resurrected via a stale key.
    path = tmp_path / "as-state.json"
    allowed = "https://client.example/cb"
    p1 = _provider(store_path=path, allowed_redirect_uris=frozenset({allowed}))
    status, reg = p1.register(json.dumps({"redirect_uris": [allowed]}).encode())
    assert status == 201
    cid = reg["client_id"]
    p2 = _provider(store_path=path)  # restart WITHOUT the allowlist entry
    _, challenge = client_oauth.generate_pkce()
    out = p2.authorize(
        {
            "client_id": cid,
            "response_type": "code",
            "redirect_uri": allowed,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        "alice",
        "https://gw.example",
    )
    assert out["kind"] == "bad_request"
    # Restarted WITH the allowlist entry, the registration keeps working.
    p3 = _provider(store_path=path, allowed_redirect_uris=frozenset({allowed}))
    out = p3.authorize(
        {
            "client_id": cid,
            "response_type": "code",
            "redirect_uri": allowed,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        "alice",
        "https://gw.example",
    )
    assert out["kind"] == "redirect" and "code=" in out["location"]


def test_token_store_tombstone_missing_family_dropped(tmp_path):
    # A tombstone without the "family" KEY (not merely None) must be dropped
    # at load: the replay path subscripts tomb["family"], so trusting it
    # would 500 the token endpoint and skip the family revocation.
    path = tmp_path / "as-state.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "consumed_refresh": {
                    "rt-no-family": {"consumed_at": 1000.0, "expires_at": 4102444800.0},
                    "rt-ok": {
                        "family": None,
                        "consumed_at": 1000.0,
                        "expires_at": 4102444800.0,
                    },
                },
                "refresh": {
                    "rt-no-resource": {
                        "user": "alice",
                        "client_id": "c",
                        "scope": "",
                        "family": None,
                        "expires_at": 4102444800.0,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    p = _provider(store_path=path)
    assert set(p._consumed_refresh) == {"rt-ok"}
    # A grant record missing the "resource" KEY is dropped for the same
    # reason (the refresh path subscripts entry["resource"]).
    assert p._refresh == {}


def test_token_store_persist_now_raises_on_unwritable_path(tmp_path):
    target = tmp_path / "occupied-dir"
    target.mkdir()  # an existing directory: os.replace onto it must fail
    p = _provider(store_path=target)
    with pytest.raises(OSError):
        p.persist_now()


def test_token_store_persist_now_creates_file_at_startup(tmp_path):
    path = tmp_path / "as-state.json"
    p = _provider(store_path=path)
    p.persist_now()
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 1


def test_serve_main_token_store_unwritable_fails_fast(tmp_path):
    # A --token-store pointing at an existing directory must abort startup
    # (parser.error), not silently run in-memory-only after logging that
    # persistence is on.
    target = tmp_path / "state-dir"
    target.mkdir()
    with pytest.raises(SystemExit):
        server.serve_main(
            [
                "--enable-oauth",
                "--dev-user",
                "a",
                "--token-store",
                str(target),
                "--",
                "true",
            ]
        )


def test_token_store_sidecar_lock_refuses_second_holder(tmp_path):
    # The in-test skip below handles a platform with no lock primitive
    # (_acquire_store_lock returns None there).
    path = tmp_path / "as-state.json"
    fd1 = server._acquire_store_lock(path)
    if fd1 is None:
        pytest.skip("no lock primitive on this platform")
    try:
        with pytest.raises(OSError):
            server._acquire_store_lock(path)
    finally:
        os.close(fd1)
    # Released: a new holder succeeds.
    fd2 = server._acquire_store_lock(path)
    assert fd2 is not None
    os.close(fd2)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_token_store_mkdir_private_tightens_intermediates(tmp_path):
    deep = tmp_path / "a" / "b" / "c"
    server._mkdir_private(deep)
    for d in (tmp_path / "a", tmp_path / "a" / "b", deep):
        assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


def test_token_store_allowlist_drop_warning_names_client(tmp_path, capsys):
    path = tmp_path / "as-state.json"
    allowed = "https://client.example/cb"
    p1 = _provider(store_path=path, allowed_redirect_uris=frozenset({allowed}))
    status, reg = p1.register(json.dumps({"redirect_uris": [allowed]}).encode())
    assert status == 201
    _provider(store_path=path)  # restart without the allowlist entry
    err = capsys.readouterr().err
    assert "dropping persisted client registration" in err
    assert reg["client_id"] in err


# --- cross-SDK guard tests (#273) ---


def test_register_ignores_application_type(oauth_gateway):
    # SEP-837 clients send RFC 7591 `application_type: "native"`; per RFC 7591
    # Sec. 2 a server ignores client metadata it does not understand, so
    # registration must still return 201. Guards against ever rejecting
    # unknown metadata fields.
    base, _ = oauth_gateway
    r = httpx.post(
        base + "/register",
        json={"redirect_uris": [_REDIRECT], "application_type": "native"},
        timeout=10,
    )
    assert r.status_code == 201, r.text
    assert r.json()["client_id"]


def test_token_response_is_identity_encoded(oauth_gateway):
    # No Content-Encoding on /token responses: a compressed body breaks
    # clients that JSON.parse the raw bytes (the typescript-sdk#2408 failure
    # class). httpx headers are case-insensitive.
    base, _ = oauth_gateway
    _, _, _, _, tok = _full_flow(base)
    assert tok.status_code == 200, tok.text
    assert "content-encoding" not in tok.headers
    assert tok.headers["content-type"] == "application/json"
