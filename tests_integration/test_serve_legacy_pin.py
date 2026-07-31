"""Legacy pin suite for `mcp-stdio serve` — the AC2 evidence base (#270 P3-0).

WHAT THIS IS FOR. Phase 3 grows serve a modern (2026-07-28) face: a
per-request-stateless dispatch path, `server/discover`, header/`_meta`
validation and `resultType`/`ttlMs`/`cacheScope` stamping. AC2 says the
legacy path survives that byte-untouched. This file is the evidence:
**every later Phase 3 PR must keep it green with zero diffs.** A diff here
is either a bug or a deliberate, reviewed behavior change — and the point
is that it can be neither silent nor accidental.

It therefore pins TODAY'S behavior, not the spec's or the design's. Where
the P3-0 scope note's label and the code disagree, the code wins and the
divergence is called out in the test's own docstring (see
`test_notification_post_needs_a_session_first`).

Assertion style, tuned for a zero-diff invariant:
- exact status codes and exact JSON-RPC error CODES (a widened error code
  is precisely what P3-A ships, and it must move a test here);
- wire-visible contract fields (`Mcp-Session-Id` presence and echo, the
  `id` correlation, `result` vs `error`);
- NOT full response bodies — the child's payloads are our own fixture and
  restating them here would pin the fixture, not the gateway.
"""

from __future__ import annotations

import json
import threading

import httpx
import pytest

from ._legacy_child import (
    LEGACY_PROTOCOL_VERSION,
    PUSH_NOTIFICATION,
    SERVER_NAME,
    TOOLS,
)
from .conftest import QUIESCENCE_WINDOW, wait_until

# Serve answers EVERY error path through `_error_body`, which hardwires
# -32000 (`server.py`'s "Build a JSON-RPC error response line (-32000
# server error)"). P3-A ships a code-bearing `_error_body` and starts
# emitting -32020/-32602/-32022 on the MODERN path; pinning the current
# value on the legacy paths is what makes that diff visible and
# intentional rather than a silent widening.
LEGACY_ERROR_CODE = -32000


def _init_message(req_id: object = "init") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "initialize",
        "params": {
            "protocolVersion": LEGACY_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "p3-0-pin-suite", "version": "0"},
        },
    }


def _error_of(resp: httpx.Response) -> dict:
    body = resp.json()
    assert "error" in body, f"expected a JSON-RPC error, got {body}"
    return body["error"]


# --- initialize -> tools flow --------------------------------------------


def test_initialize_mints_a_session_and_returns_the_child_result(serve_gateway):
    """`initialize` opens a session and its result reaches the client VERBATIM.

    Two pins in one, because they are the same wire event: the minted
    `Mcp-Session-Id` (MCP Streamable HTTP session management item 1) is
    returned as a response HEADER, and serve forwards the child's
    `InitializeResult` untouched — no `resultType`, no caching hints, no
    rewriting of `serverInfo`. P3-B captures this result to source
    discover's `serverInfo`; capturing it must not change what the LEGACY
    client sees.
    """
    resp = serve_gateway.post(_init_message())
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    sid = resp.headers.get("mcp-session-id")
    assert sid, "initialize must mint a session id"

    body = resp.json()
    assert body["id"] == "init"
    result = body["result"]
    assert result["protocolVersion"] == LEGACY_PROTOCOL_VERSION
    assert result["serverInfo"]["name"] == SERVER_NAME
    # The legacy contract has no `resultType` and no caching hints. Both
    # are what P3-B adds on the MODERN path only; their absence here is
    # the AC2 assertion.
    assert "resultType" not in result
    assert "ttlMs" not in result and "cacheScope" not in result

    serve_gateway.delete(sid=sid)


def test_tools_list_and_call_round_trip_on_a_session(serve_gateway):
    """The flow a real client runs: list the tools, then call one.

    `tools/list` and `tools/call` are two of the six operations P3-B
    stamps caching hints onto (`tools/call` is not among them, `tools/list`
    is), so this is the before-picture for that diff. Today both are
    forwarded and returned verbatim.
    """
    sid = serve_gateway.open_session()

    listed = serve_gateway.post(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, sid=sid
    )
    assert listed.status_code == 200
    assert listed.headers.get("mcp-session-id") == sid
    body = listed.json()
    assert body["id"] == 1
    assert [tool["name"] for tool in body["result"]["tools"]] == [
        tool["name"] for tool in TOOLS
    ]
    assert "resultType" not in body["result"]
    assert "ttlMs" not in body["result"]

    called = serve_gateway.post(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "hi"}},
        },
        sid=sid,
    )
    assert called.status_code == 200
    body = called.json()
    assert body["id"] == 2
    payload = json.loads(body["result"]["content"][0]["text"])
    assert payload["echoed"] == {"text": "hi"}
    assert body["result"]["isError"] is False

    serve_gateway.delete(sid=sid)


def test_child_error_is_forwarded_as_the_childs_own_code(serve_gateway):
    """A child's JSON-RPC error rides through with ITS code, not serve's.

    Pins that serve does not re-wrap a backend error into its own -32000,
    and — for P3-B — that an error result is not a `resultType: "complete"`
    candidate the stamping seam may touch.
    """
    sid = serve_gateway.open_session()
    resp = serve_gateway.post(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "nope", "arguments": {}},
        },
        sid=sid,
    )
    # The child answered; the TRANSPORT succeeded. Serve reports 200 and
    # lets the JSON-RPC error speak for itself.
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == 7
    assert body["error"]["code"] == -32602
    serve_gateway.delete(sid=sid)


# --- session lifecycle ---------------------------------------------------


def test_sessionless_post_is_400(serve_gateway):
    """A non-initialize POST with no `Mcp-Session-Id` -> 400.

    MCP Streamable HTTP session management item 2. Pinned WITH the error
    code because P3-A's whole subject is new 4xx paths carrying new codes;
    the legacy one must stay -32000.
    """
    resp = serve_gateway.post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert resp.status_code == 400
    error = _error_of(resp)
    assert error["code"] == LEGACY_ERROR_CODE
    # The id is echoed so the client can correlate the rejection.
    assert resp.json()["id"] == 1
    # No session was minted, so no session header may leak out.
    assert "mcp-session-id" not in resp.headers


def test_unknown_session_is_404_and_the_client_recovers_by_reinitializing(
    serve_gateway,
):
    """An unknown/terminated session -> 404, and re-initialize recovers.

    Item 3, and the RECOVERY half is the part that matters: 404 is the
    signal that drives a client's re-initialize, so the pin covers the
    whole loop rather than just the status code. A later PR that turned
    404 into 400 would keep a status-only test green while breaking every
    real client's recovery path.
    """
    resp = serve_gateway.post(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, sid="0" * 32
    )
    assert resp.status_code == 404
    assert _error_of(resp)["code"] == LEGACY_ERROR_CODE

    # Recovery: a fresh initialize mints a NEW id that works.
    reopened = serve_gateway.post(_init_message("reinit"))
    assert reopened.status_code == 200
    new_sid = reopened.headers.get("mcp-session-id")
    assert new_sid and new_sid != "0" * 32

    after = serve_gateway.post(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid=new_sid
    )
    assert after.status_code == 200
    serve_gateway.delete(sid=new_sid)


def test_delete_terminates_the_session_and_later_use_is_404(serve_gateway):
    """DELETE ends a session (item 5); the id is dead afterwards.

    D2 of the Phase 3 re-scope keeps DELETE on the legacy transport
    untouched (the spec's 405-on-DELETE is SHOULD-strength and scoped to
    modern-ONLY servers). This pin is what would catch a blanket 405.
    """
    sid = serve_gateway.open_session()

    ended = serve_gateway.delete(sid=sid)
    assert ended.status_code == 200
    assert ended.headers.get("mcp-session-id") == sid

    reused = serve_gateway.post(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, sid=sid
    )
    assert reused.status_code == 404


def test_sessionless_and_unknown_delete_mirror_the_post_statuses(serve_gateway):
    """DELETE reports the same 400/404 split as POST for the same conditions."""
    assert serve_gateway.delete().status_code == 400
    assert serve_gateway.delete(sid="0" * 32).status_code == 404


def test_notification_post_needs_a_session_first(serve_gateway):
    """A notification POST is 202 ON A SESSION, and 400 without one.

    REALITY-VS-LABEL: the P3-0 scope note lists "202 for notification
    POSTs" flatly. The code does not special-case notifications before
    session resolution — `is_init` is false for a notification, so it goes
    through `_resolve_session` like any other non-initialize POST and a
    SESSIONLESS notification is 400, never 202. Pinned as it is, because
    obligation O9 ("header requirements for notification POSTs are not
    defined by this revision") makes notifications an exemption candidate
    in P3-A, and this test is what says which exemption was actually
    granted.
    """
    assert (
        serve_gateway.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    ).status_code == 400

    sid = serve_gateway.open_session()
    accepted = serve_gateway.post(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid=sid
    )
    assert accepted.status_code == 202
    assert accepted.headers.get("mcp-session-id") == sid
    # 202 carries no body — a notification has no id to answer under.
    assert accepted.content == b""
    serve_gateway.delete(sid=sid)


def test_duplicate_in_flight_id_is_409(serve_gateway, tmp_path):
    """Two DIFFERENT payloads under one id, both in flight -> 409.

    The backend's two replies would both carry that id and could not be
    correlated, so serve rejects the second rather than cross-wiring a
    reply. (A same-PAYLOAD retry is piggybacked instead, which is why the
    collider below calls a different tool.)

    The pending slot is first-come, so the ORDER matters and is made
    deterministic rather than assumed: the child creates `started_marker`
    before it sleeps, and the collider is sent only once that file is
    observed (rules 1 and 4). Retrying the collider until it happened to
    lose the race would be the wrong fix — a collider that registers FIRST
    makes serve reject the slow request instead, after which nothing is in
    flight and every later attempt legitimately returns 200.
    """
    sid = serve_gateway.open_session()
    marker = tmp_path / "slow-started"
    slow_status: list[int] = []

    def _slow() -> None:
        resp = serve_gateway.post(
            {
                "jsonrpc": "2.0",
                "id": "shared",
                "method": "tools/call",
                "params": {
                    "name": "slow",
                    "arguments": {"delay": 3.0, "started_marker": str(marker)},
                },
            },
            sid=sid,
            timeout=30.0,
        )
        slow_status.append(resp.status_code)

    thread = threading.Thread(target=_slow, daemon=True)
    thread.start()
    try:
        wait_until(
            marker.exists,
            10.0,
            "the child to start the slow call",
            diagnose=serve_gateway.diagnose,
        )
        conflict = serve_gateway.post(
            {
                "jsonrpc": "2.0",
                "id": "shared",
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "collide"}},
            },
            sid=sid,
        )
        assert conflict.status_code == 409
        assert _error_of(conflict)["code"] == LEGACY_ERROR_CODE
        assert conflict.json()["id"] == "shared"
    finally:
        thread.join(timeout=30)
        serve_gateway.delete(sid=sid)

    # The original request was never disturbed by the rejection.
    assert slow_status == [200]


# --- GET SSE -------------------------------------------------------------


def test_get_opens_an_sse_stream_carrying_server_initiated_messages(serve_gateway):
    """GET streams the child's server-initiated traffic for that session.

    The other half of D2: a dual-era serve keeps GET, because the legacy
    transport needs it. Pinned end to end — headers, then an actual
    notification pushed by the child — so a 405 or a header change cannot
    pass.
    """
    sid = serve_gateway.open_session()
    received: list[dict] = []
    opened = threading.Event()
    stop = threading.Event()

    def _read() -> None:
        try:
            with httpx.stream(
                "GET",
                serve_gateway.url,
                headers={"Mcp-Session-Id": sid},
                timeout=20.0,
            ) as resp:
                assert resp.status_code == 200
                assert resp.headers["content-type"] == "text/event-stream"
                assert resp.headers.get("mcp-session-id") == sid
                opened.set()
                for line in resp.iter_lines():
                    if line.startswith("data: "):
                        received.append(json.loads(line[len("data: ") :]))
                        stop.set()
                        return
        except httpx.HTTPError:  # pragma: no cover — torn down mid-read
            opened.set()

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    try:
        wait_until(opened.is_set, 10.0, "the SSE stream to open")
        # The child emits its notification when it sees this one.
        pushed = serve_gateway.post(
            {"jsonrpc": "2.0", "method": "notifications/push"}, sid=sid
        )
        assert pushed.status_code == 202
        wait_until(
            stop.is_set,
            10.0,
            "the pushed notification to arrive on the SSE stream",
            diagnose=serve_gateway.diagnose,
        )
    finally:
        reader.join(timeout=10)
        serve_gateway.delete(sid=sid)

    assert len(received) == 1
    assert received[0]["method"] == PUSH_NOTIFICATION["method"]
    assert received[0]["params"] == PUSH_NOTIFICATION["params"]


def test_get_mirrors_the_post_session_statuses(serve_gateway):
    """Sessionless GET -> 400, unknown session -> 404, same as POST."""
    sessionless = httpx.get(serve_gateway.url, timeout=10.0)
    assert sessionless.status_code == 400
    assert _error_of(sessionless)["code"] == LEGACY_ERROR_CODE

    unknown = httpx.get(
        serve_gateway.url, headers={"Mcp-Session-Id": "0" * 32}, timeout=10.0
    )
    assert unknown.status_code == 404


# --- what serve must NOT do yet ------------------------------------------


@pytest.mark.timeout(45)
def test_modern_markers_are_not_answered_yet(serve_factory):
    """A modern-shaped request gets today's legacy treatment, not a modern one.

    The before-picture for P3-A and P3-B in one assertion: a request
    carrying modern per-request `_meta` — the exact positive evidence D5
    makes the era predicate look for — is NOT special-cased today. It
    falls into the sessionless-POST path and gets 400, and
    `server/discover` gets the same. When P3-A lands, `_meta` presence
    starts routing to validation; when P3-B lands, discover is answered.
    Both are visible here as an intentional diff.

    A dedicated gateway (not the shared one) because this is the test most
    likely to change shape in a later PR, and it must not leave the module
    fixture in a state a rewrite could disturb.
    """
    gateway = serve_factory()

    modern = gateway.post(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            },
        },
        headers={"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"},
    )
    assert modern.status_code == 400
    assert _error_of(modern)["code"] == LEGACY_ERROR_CODE

    discover = gateway.post({"jsonrpc": "2.0", "id": 2, "method": "server/discover"})
    assert discover.status_code == 400
    assert _error_of(discover)["code"] == LEGACY_ERROR_CODE


def test_a_quiet_session_receives_nothing_unsolicited(serve_gateway):
    """Nothing arrives on a session the client did not ask for.

    Rule 5's bounded quiescence check, justified by AC2: P3-B adds a
    result-rewrite seam and a pooled modern child. Neither may start
    pushing traffic at a LEGACY session. Bounded window, assertion on the
    collected content — never on how long it waited.
    """
    sid = serve_gateway.open_session()
    seen: list[dict] = []
    opened = threading.Event()

    def _read() -> None:
        try:
            with httpx.stream(
                "GET",
                serve_gateway.url,
                headers={"Mcp-Session-Id": sid},
                timeout=QUIESCENCE_WINDOW + 5.0,
            ) as resp:
                opened.set()
                for line in resp.iter_lines():
                    if line.startswith("data: "):
                        seen.append(json.loads(line[len("data: ") :]))
        except httpx.HTTPError:  # pragma: no cover — closed at teardown
            opened.set()

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    try:
        wait_until(opened.is_set, 10.0, "the SSE stream to open")
        # Deliberately idle for one bounded window.
        reader.join(timeout=QUIESCENCE_WINDOW)
    finally:
        serve_gateway.delete(sid=sid)
        reader.join(timeout=10)

    assert seen == [], f"unsolicited traffic on a quiet legacy session: {seen}"
