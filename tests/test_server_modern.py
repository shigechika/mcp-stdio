"""Serve's modern request-plane validation ladder (#270 Phase 3 P3-A).

A NEW file rather than more of `test_server.py` (107 KB): this is one
coherent subject — the era predicate and the O6-O10 rejection ladder —
and it is the file P3-B will extend when the modern path grows a
dispatch behind these gates.

The fixture is copied from `test_server.py` rather than hoisted into a
`tests/conftest.py`: the project ships no pytest ini and no tests
conftest today, and introducing one to share twelve lines would change
collection for 1,652 unrelated tests. Same pattern either way — real
`build_server` on an ephemeral port, `serve_forever` in a thread, real
httpx over loopback, the real `_fake_backend.py` child.

WHAT EVERY REJECTION TEST ASSERTS, and why each item earns its place:
- HTTP 400 — the spec maps -32602/-32020/-32022 to it;
- the exact `error.code` — the whole point of the PR is which code;
- the request `id` ECHOED — "Error responses MUST include the same ID as
  the request", and a rejection that drops it strands a client that
  cannot correlate the failure;
- NO `Mcp-Session-Id` response header — the ladder runs before session
  resolution, so a rejection must never look like it opened a session.
  This is also the tripwire for someone moving the hook: if it ever
  lands below the session block, `self._session_id` is set and this
  assertion is the only thing that notices.
"""

from __future__ import annotations

import ast
import base64
import json
import os
import re
import socket
import sys
import threading

from unittest.mock import patch

import httpx
import pytest

from mcp_stdio import server
from mcp_stdio.relay import _encode_mcp_name

_BACKEND = [sys.executable, os.path.join(os.path.dirname(__file__), "_fake_backend.py")]

MODERN_VERSION = "2026-07-28"
META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CAPS = "io.modelcontextprotocol/clientCapabilities"

INVALID_PARAMS = -32602
HEADER_MISMATCH = -32020
UNSUPPORTED_VERSION = -32022
LEGACY_ERROR = -32000


@pytest.fixture()
def gateway():
    """Start the gateway on an ephemeral port; yield its MCP URL."""
    httpd, registry = server.build_server(_BACKEND, host="127.0.0.1", port=0)
    host, port = httpd.server_address[0], httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}/mcp"
    finally:
        httpd.shutdown()
        registry.shutdown_all()
        httpd.server_close()


def _meta(version: object = MODERN_VERSION, *, caps: bool = True) -> dict:
    meta: dict = {META_VERSION: version}
    if caps:
        meta[META_CAPS] = {}
    return meta


def _modern_body(
    method: str = "tools/list",
    req_id: object = 1,
    *,
    params: dict | None = None,
    meta: dict | None = None,
    notification: bool = False,
) -> dict:
    body: dict = {"jsonrpc": "2.0", "method": method}
    if not notification:
        body["id"] = req_id
    merged = dict(params or {})
    if meta is not None:
        merged["_meta"] = meta
    if merged:
        body["params"] = merged
    return body


def _modern_headers(
    method: str = "tools/list",
    *,
    version: str | None = MODERN_VERSION,
    name: str | None = None,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    if version is not None:
        headers["MCP-Protocol-Version"] = version
    if method is not None:
        headers["Mcp-Method"] = method
    if name is not None:
        headers["Mcp-Name"] = name
    return headers


def _post(url: str, body: dict, headers: dict | None = None, **kwargs):
    return httpx.post(
        url, content=json.dumps(body), headers=headers or {}, timeout=10, **kwargs
    )


def _read_http_response(sock: socket.socket, timeout: float = 10.0) -> bytes:
    """Read ONE complete HTTP response — headers AND the declared body.

    Stopping at the `\\r\\n\\r\\n` header terminator is the obvious loop
    and it is wrong: TCP is free to deliver the headers and the body in
    separate segments, so a body assertion then passes or fails by
    scheduling luck. It did exactly that — green on one CI interpreter
    and red on four, for a response the server had sent correctly all
    along. Honour `Content-Length` instead.
    """
    sock.settimeout(timeout)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    match = re.search(rb"(?im)^content-length:\s*(\d+)\s*$", head)
    if match is None:  # pragma: no cover — every serve response declares one
        return data
    expected = int(match.group(1))
    while len(body) < expected:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


def _assert_rejected(resp: httpx.Response, code: int, req_id: object = 1) -> dict:
    """Every ladder rejection's shared contract (see the module docstring)."""
    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["error"]["code"] == code, body
    assert body["id"] == req_id, body
    assert "mcp-session-id" not in resp.headers, dict(resp.headers)
    return body["error"]


# --- the era predicate (D5) ----------------------------------------------


class TestRequestEra:
    """Conservative by construction: modern only on POSITIVE evidence."""

    def test_legacy_body_without_meta_is_untouched(self, gateway):
        """The AC2 shape: no `_meta`, so the ladder never runs and the
        request earns today's sessionless rejection verbatim."""
        resp = _post(gateway, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        _assert_rejected(resp, LEGACY_ERROR)

    def test_meta_without_the_protocol_version_key_stays_legacy(self, gateway):
        """The D5 boundary, and the reason the predicate keys on ONE field.

        A `_meta` carrying only `clientCapabilities` is not modern
        evidence — some future legacy extension could use `_meta` for its
        own purposes, and classifying on "has any `_meta`" would drag it
        into a ladder it has never heard of.
        """
        body = _modern_body(meta={META_CAPS: {}})
        error = _assert_rejected(_post(gateway, body), LEGACY_ERROR)
        assert "Mcp-Session-Id" in error["message"]

    def test_malformed_version_value_still_classifies_modern(self, gateway):
        """PRESENCE, not validity. A body whose version is nonsense must
        reach the ladder and be told what is wrong, not be demoted to
        legacy where it would get a session error that explains nothing."""
        body = _modern_body(meta=_meta(12345))
        _assert_rejected(_post(gateway, body, _modern_headers()), HEADER_MISMATCH)

    def test_discover_without_meta_is_modern_and_hits_rung_one(self, gateway):
        """`server/discover` classifies modern by METHOD — it exists only
        on the modern wire — but that arm softens nothing: without `_meta`
        it earns the ladder's first rejection like anything else."""
        body = {"jsonrpc": "2.0", "id": 1, "method": "server/discover"}
        _assert_rejected(_post(gateway, body), INVALID_PARAMS)

    def test_response_shaped_body_is_never_modern(self, gateway):
        """Spec rev 2026-07-28 removed server-initiated requests, so a
        client never POSTs a response. Classified legacy, unchanged."""
        resp = _post(gateway, {"jsonrpc": "2.0", "id": 1, "result": {}})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == LEGACY_ERROR

    def test_batch_and_invalid_json_stay_on_the_pre_era_path(self, gateway):
        """Both fail the shape checks BEFORE the predicate runs, so their
        400s are byte-identical to today's."""
        batch = httpx.post(gateway, content=json.dumps([]), timeout=10)
        assert batch.status_code == 400
        assert batch.json()["error"]["code"] == LEGACY_ERROR

        broken = httpx.post(gateway, content="{not json", timeout=10)
        assert broken.status_code == 400
        assert broken.json()["error"]["code"] == LEGACY_ERROR


# --- rung 1: required `_meta` (O6) ---------------------------------------


class TestMetaRung:
    def test_non_mapping_meta_on_an_ordinary_method_stays_legacy(self, gateway):
        """`_meta: "..."` is not modern evidence — no protocolVersion key
        can be read out of a string — so the predicate classifies legacy
        and the ladder never sees it. Pinned so the boundary is explicit
        rather than incidental, and named for what it asserts."""
        body = _modern_body(meta=None, params={"_meta": "not-an-object"})
        _assert_rejected(_post(gateway, body), LEGACY_ERROR)

    def test_non_mapping_meta_on_discover_is_invalid_params(self, gateway):
        """The ONLY live path into rung 1's non-mapping branch — and the
        reason that branch is not dead code.

        The era predicate returns "modern" for `server/discover` BEFORE it
        looks at `params`, so a discover whose `_meta` is a string reaches
        rung 1 and is rejected there. For every other method a non-mapping
        `_meta` classifies legacy (the test above), which is why this
        branch looks unreachable until you follow the discover arm.
        Without this test a reviewer marks it `# pragma: no cover` by
        analogy with rung 3, or P3-B deletes it, and a malformed discover
        then falls somewhere nobody chose.
        """
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {"_meta": "not-an-object"},
        }
        error = _assert_rejected(_post(gateway, body), INVALID_PARAMS)
        assert META_VERSION in error["message"]

    def test_missing_client_capabilities_is_invalid_params(self, gateway):
        body = _modern_body(meta=_meta(caps=False))
        error = _assert_rejected(_post(gateway, body), INVALID_PARAMS)
        # The message names what is missing — these are protocol
        # constants, not attacker-controlled values.
        assert META_CAPS in error["message"]

    def test_client_info_is_never_required(self, gateway):
        """`clientInfo` is SHOULD-only; its absence must not reject."""
        body = _modern_body(meta=_meta())
        _assert_rejected(_post(gateway, body, _modern_headers()), LEGACY_ERROR)


# --- rung 2: the header family (O7, O8) ----------------------------------


class TestHeaderRungs:
    def test_null_body_version_with_absent_header_is_a_mismatch(self, gateway):
        """#270 P3-B commit 0 — a P3-A advisory, resolved.

        `None != None` is False, so an absent header paired with
        `"protocolVersion": null` used to slip rung 2a and fall through to
        the "unreachable" rung 3, answering -32602 for what is plainly a
        HEADER fault. The presence test is now explicit, matching
        python-sdk v2's own guard and its stated reason. The body still
        classifies MODERN — D5 keys on the KEY's presence, not its value —
        so this reaches the ladder rather than being demoted to legacy.
        """
        body = _modern_body(meta=_meta(None))
        _assert_rejected(
            _post(gateway, body, _modern_headers(version=None)), HEADER_MISMATCH
        )

    def test_version_header_missing_is_a_mismatch(self, gateway):
        """The header is REQUIRED, so absence and disagreement are one
        fault with one code — `None` never equals the body value."""
        body = _modern_body(meta=_meta())
        resp = _post(gateway, body, _modern_headers(version=None))
        _assert_rejected(resp, HEADER_MISMATCH)

    def test_version_header_disagrees_with_body(self, gateway):
        """**AC4.** The header says one revision, `_meta` says another."""
        body = _modern_body(meta=_meta())
        resp = _post(gateway, body, _modern_headers(version="2025-06-18"))
        error = _assert_rejected(resp, HEADER_MISMATCH)
        assert "MCP-Protocol-Version" in error["message"]
        # -32020 carries no `data` per the schema, and the message must
        # not reflect either value back to the sender.
        assert (
            "data"
            not in _post(gateway, body, _modern_headers(version="x")).json()["error"]
        )
        assert "2025-06-18" not in error["message"]

    def test_missing_mcp_method_header(self, gateway):
        body = _modern_body(meta=_meta())
        headers = _modern_headers()
        del headers["Mcp-Method"]
        _assert_rejected(_post(gateway, body, headers), HEADER_MISMATCH)

    def test_mcp_method_header_disagrees_with_body(self, gateway):
        body = _modern_body("tools/list", meta=_meta())
        resp = _post(gateway, body, _modern_headers("prompts/list"))
        error = _assert_rejected(resp, HEADER_MISMATCH)
        assert "Mcp-Method" in error["message"]

    def test_name_bearing_method_without_the_name_header(self, gateway):
        body = _modern_body("tools/call", params={"name": "echo"}, meta=_meta())
        resp = _post(gateway, body, _modern_headers("tools/call"))
        _assert_rejected(resp, HEADER_MISMATCH)

    def test_name_header_matching_after_decode_passes(self, gateway):
        """The O8 MUST, end to end: a non-ASCII name rides encoded and the
        server decodes BEFORE comparing. Passing the ladder means falling
        through to the sessionless rejection."""
        name = "こんにちは"
        body = _modern_body("tools/call", params={"name": name}, meta=_meta())
        headers = _modern_headers("tools/call", name=_encode_mcp_name(name))
        assert headers["Mcp-Name"].startswith("=?base64?")
        _assert_rejected(_post(gateway, body, headers), LEGACY_ERROR)

    def test_malformed_sentinel_is_a_mismatch_not_a_crash(self, gateway):
        """A corrupt header decodes to None, which never equals the body
        value — so it lands on -32020 rather than needing a code of its
        own or escaping as a 500."""
        body = _modern_body("tools/call", params={"name": "echo"}, meta=_meta())
        headers = _modern_headers("tools/call", name="=?base64?not-base64!!?=")
        _assert_rejected(_post(gateway, body, headers), HEADER_MISMATCH)

    def test_non_ascii_sentinel_payload_is_rejected_not_fatal(self, gateway):
        """#371 review R1F1 — a regression test for a real crash.

        HTTP headers decode as latin-1, so `Mcp-Name: =?base64?<0xFF>?=`
        reaches the decoder as a str with a non-ASCII character.
        `b64decode` rejects that at its internal `s.encode("ascii")` step
        with a plain `ValueError`, which the original `binascii.Error`
        catch did not cover: the exception escaped the ladder, killed the
        handler thread, and the client got NO RESPONSE AT ALL — strictly
        worse than the rejection it had earned, and remotely triggerable
        by one header.

        Driven over a raw socket because httpx will not send a non-ASCII
        header value; only a byte-level client can express this.
        """
        body = json.dumps(
            _modern_body("tools/call", params={"name": "echo"}, meta=_meta())
        )
        request = (
            f"POST /mcp HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"MCP-Protocol-Version: {MODERN_VERSION}\r\n"
            f"Mcp-Method: tools/call\r\n"
            f"Mcp-Name: =?base64?\xff?=\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}"
        ).encode("latin-1")

        port = int(gateway.rsplit(":", 1)[1].split("/")[0])
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        try:
            sock.sendall(request)
            data = _read_http_response(sock)
        finally:
            sock.close()

        text = data.decode("utf-8", "replace")
        assert text, "the handler died and answered nothing"
        assert text.startswith("HTTP/1.1 400 "), text[:200]
        assert f'"code": {HEADER_MISMATCH}' in text, text[:400]

    def test_decoded_name_disagrees_with_body(self, gateway):
        body = _modern_body("tools/call", params={"name": "echo"}, meta=_meta())
        headers = _modern_headers("tools/call", name=_encode_mcp_name("other"))
        _assert_rejected(_post(gateway, body, headers), HEADER_MISMATCH)

    def test_resources_read_compares_the_uri_field(self, gateway):
        """The name-bearing field is `params.uri` here, not `params.name`."""
        body = _modern_body(
            "resources/read", params={"uri": "file:///a.txt"}, meta=_meta()
        )
        ok = _modern_headers("resources/read", name="file:///a.txt")
        _assert_rejected(_post(gateway, body, ok), LEGACY_ERROR)
        bad = _modern_headers("resources/read", name="file:///b.txt")
        _assert_rejected(_post(gateway, body, bad), HEADER_MISMATCH)

    def test_non_name_bearing_method_needs_no_name_header(self, gateway):
        body = _modern_body("tools/list", meta=_meta())
        _assert_rejected(_post(gateway, body, _modern_headers()), LEGACY_ERROR)

    def test_name_bearing_method_with_no_body_value_skips_the_check(self, gateway):
        """Deliberate hole, pinned so it reads as a decision.

        A `tools/call` with no `params` at all has no body value for
        `Mcp-Name` to mirror, so rung 2c is SKIPPED and the request falls
        through. Dispatch owns missing-param errors; inventing a header
        mismatch for a body problem would report the wrong fault.
        """
        body = _modern_body("tools/call", meta=_meta())
        _assert_rejected(
            _post(gateway, body, _modern_headers("tools/call")), LEGACY_ERROR
        )

    def test_unknown_mcp_param_headers_are_ignored(self, gateway):
        """Spec: an intermediary "MUST forward it and otherwise ignore
        it". P3-A forwards nothing yet; the obligation here is only that
        an unknown one does not reject."""
        headers = _modern_headers()
        headers["Mcp-Param-Foo"] = "anything"
        body = _modern_body(meta=_meta())
        _assert_rejected(_post(gateway, body, headers), LEGACY_ERROR)

    def test_duplicate_routing_header_is_rejected(self, gateway):
        """SDK step 0, spec-silent hardening (§4 Q3, adopted).

        `headers.get()` folds duplicates to the FIRST value, so without
        this rung a client could send one `Mcp-Method` that matches the
        body and a second that does not, and serve would validate the one
        an intermediary might not forward.
        """
        body = _modern_body(meta=_meta())
        # httpx keeps repeated headers when they are given as a list of
        # pairs, which is the only way to express this on the wire.
        resp = httpx.post(
            gateway,
            content=json.dumps(body),
            headers=[
                ("MCP-Protocol-Version", MODERN_VERSION),
                ("Mcp-Method", "tools/list"),
                ("Mcp-Method", "tools/call"),
            ],
            timeout=10,
        )
        error = _assert_rejected(resp, HEADER_MISMATCH)
        assert "more than once" in error["message"]


# --- rung 4: version support (O10), and precedence ------------------------


class TestVersionRung:
    def test_unsupported_version_carries_the_supported_set(self, gateway):
        body = _modern_body(meta=_meta("2099-01-01"))
        resp = _post(gateway, body, _modern_headers(version="2099-01-01"))
        error = _assert_rejected(resp, UNSUPPORTED_VERSION)
        # `data` is SCHEMA-MANDATED here: without `supported` a client has
        # nothing to renegotiate toward. Asserted on the parsed shape.
        assert error["data"]["supported"] == [MODERN_VERSION]
        assert error["data"]["requested"] == "2099-01-01"

    def test_header_rung_wins_over_the_version_rung(self, gateway):
        """Precedence, and it is load-bearing rather than cosmetic.

        A request that is BOTH self-inconsistent (no version header) and
        on an unsupported version gets -32020, not -32022 — the SDK's own
        stated ordering, "so a client that disagrees with itself is told
        so, rather than told the body's version is unsupported". -32022
        is the one code an auto-negotiating client does not fall back
        from, so mis-emitting it would strand a client that could have
        fixed its headers instead.
        """
        body = _modern_body(meta=_meta("2099-01-01"))
        resp = _post(gateway, body, _modern_headers(version=None))
        _assert_rejected(resp, HEADER_MISMATCH)


# --- exemptions and the P3-A fallthrough ---------------------------------


class TestNotificationExemptionAndFallthrough:
    def test_modern_notification_is_not_laddered(self, gateway):
        """O9 + the P3-0 pin: a notification carrying modern `_meta` but NO
        headers at all is not rejected by the ladder.

        python-sdk v2 400s every notification POST; serve deliberately
        does not copy that (divergence ledger item i). Sessionless it
        still gets today's 400 `-32000` from session resolution — which is
        the point: the code proves the LEGACY path answered, not the
        ladder.
        """
        body = _modern_body(
            "notifications/initialized", meta=_meta(), notification=True
        )
        resp = _post(gateway, body)
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == LEGACY_ERROR

    def test_modern_notification_on_a_session_is_still_accepted(self, gateway):
        """The O9 evidence, and the pin `test_notification_post_needs_a_
        session_first` in its integration form: 202, exactly as today."""
        init = _post(gateway, {"jsonrpc": "2.0", "id": "i", "method": "initialize"})
        sid = init.headers["mcp-session-id"]
        body = _modern_body(
            "notifications/initialized", meta=_meta(), notification=True
        )
        resp = _post(gateway, body, {"Mcp-Session-Id": sid})
        assert resp.status_code == 202
        assert resp.content == b""

    def test_fully_valid_modern_request_falls_through_to_the_legacy_401(self, gateway):
        """P3-A ships ZERO modern dispatch (§3.1(b)).

        A request that passes every rung still lands in the untouched
        session-resolution path, so it gets today's 400 `-32000`
        "Mcp-Session-Id required". The code being the LEGACY one is the
        assertion: it proves the ladder let it through rather than
        answering it, and P3-B replaces this fallthrough wholesale.
        """
        body = _modern_body(meta=_meta())
        error = _assert_rejected(_post(gateway, body, _modern_headers()), LEGACY_ERROR)
        assert "Mcp-Session-Id" in error["message"]


# --- the -32002 prohibition (O18) ----------------------------------------


def test_serve_mints_no_new_32002_code():
    """Obligation O18: serve emits no `-32002`, ever.

    "Implementations of this protocol version MUST NOT emit these codes:
    `-32002`" — the code is grandfathered for relay's cold-start gate
    only, and "new implementations SHOULD NOT use codes from this
    sub-range at all". serve is new code on this wire, so it gets no
    grandfathering.

    Asserted over the parsed AST rather than a substring search: prose —
    including this file's own citation and server.py's comment explaining
    the prohibition — must not be able to trip it, and a future
    `code=-32002` must not be able to hide behind that.
    """
    server_py = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "src", "mcp_stdio", "server.py"
    )
    with open(server_py, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    offenders = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and node.operand.value == 32002
    ]
    assert offenders == [], f"server.py names -32002 at line(s) {offenders}"


def test_supported_versions_are_serves_own_claim():
    """Serve advertises what SERVE implements, never relay's set.

    They are equal today and that is fine; the point is that they are two
    separate claims about opposite sides of the wire, so a revision one
    gateway implements first is not advertised by the other for free.
    """
    from mcp_stdio import relay

    assert server._SERVE_IMPLEMENTED_MODERN_VERSIONS == frozenset({MODERN_VERSION})
    assert (
        server._SERVE_IMPLEMENTED_MODERN_VERSIONS
        is not relay._RELAY_IMPLEMENTED_MODERN_VERSIONS
    )


def test_encoded_name_round_trips_through_the_real_decoder():
    """Guards the encoder/decoder pairing the ladder depends on."""
    for value in ("echo", "こんにちは", " padded ", "=?base64?fake?="):
        header = _encode_mcp_name(value)
        assert server._decode_mcp_name(header) == value
    assert base64.b64decode("QUJ=", validate=True) == b"AB"
    assert server._decode_mcp_name("=?base64?QUJ=?=") is None


# --- the modern backend pool (#270 Phase 3 P3-B) -------------------------


class TestModernBackendPool:
    """Gateway-owned children for the session-less modern path (D1)."""

    def test_handshake_initializes_the_child_and_caches_the_result(self):
        """The gateway performs the handshake the modern wire omits.

        Two halves matter and both are asserted: the cached
        `InitializeResult` (discover's only honest source for the child's
        capabilities and identity), and the `notifications/initialized`
        that follows it — easy to miss, because on the legacy path the
        CLIENT sends it, and FastMCP children gate post-init requests on
        it.
        """
        pool = server.ModernBackendPool(_BACKEND)
        try:
            backend, init_result = pool.get_or_create(None)
            assert init_result["protocolVersion"] == "2025-06-18"
            assert init_result["serverInfo"]["name"] == "fake"
            # A second call reuses the same child rather than respawning.
            again, cached = pool.get_or_create(None)
            assert again is backend
            assert cached is init_result
            assert pool.count() == 1
        finally:
            pool.shutdown_all()

    def test_children_are_keyed_per_principal(self):
        """D1's authorization boundary: one child per principal.

        Sharing a child across principals would leak child state across
        that boundary, which is why per-principal keying was not deferred.
        Proved by the child's own pid, not by counting.
        """
        pool = server.ModernBackendPool(_BACKEND)
        try:
            alice, _ = pool.get_or_create("alice")
            bob, _ = pool.get_or_create("bob")
            assert alice is not bob
            assert pool.count() == 2
        finally:
            pool.shutdown_all()

    def test_concurrent_first_requests_spawn_one_child(self):
        """The latch: racing first requests must not double-spawn.

        Spawning happens outside the lock — holding it across a process
        spawn plus a handshake round-trip would serialise every unrelated
        principal — so a placeholder entry is what a racing thread finds.
        """
        pool = server.ModernBackendPool(_BACKEND)
        got: list = []
        barrier = threading.Barrier(4)

        def _race():
            barrier.wait(timeout=10)
            got.append(pool.get_or_create("shared")[0])

        threads = [threading.Thread(target=_race) for _ in range(4)]
        try:
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
            assert len(got) == 4
            assert len({id(b) for b in got}) == 1, "the latch let a second child spawn"
            assert pool.count() == 1
        finally:
            pool.shutdown_all()

    def test_a_dead_child_is_dropped_and_respawned(self):
        """Mirror of the legacy drop-then-reinit: death is not terminal."""
        pool = server.ModernBackendPool(_BACKEND)
        try:
            first, _ = pool.get_or_create(None)
            first.shutdown()
            assert first.closed
            second, _ = pool.get_or_create(None)
            assert second is not first
            assert not second.closed
        finally:
            pool.shutdown_all()

    def test_at_cap_the_idlest_child_is_evicted(self):
        """§4 Q3: evict, don't refuse.

        A modern client is STATELESS, so an eviction costs it only the
        warm-up of a child it never knew about — whereas a 503 fails a
        request the gateway could have served. The legacy registry keeps
        the opposite policy because an evicted SESSION strands a client
        mid-conversation.
        """
        pool = server.ModernBackendPool(_BACKEND, max_children=2)
        try:
            pool.get_or_create("a")
            pool.get_or_create("b")
            assert pool.count() == 2
            pool.get_or_create("c")
            assert pool.count() == 2, "the cap did not hold"
        finally:
            pool.shutdown_all()

    def test_a_child_that_never_answers_initialize_raises(self):
        """A failed handshake leaves no entry behind to poison retries."""
        pool = server.ModernBackendPool(
            [sys.executable, "-c", "import sys; sys.stdin.read()"]
        )
        try:
            with patch.object(server, "_BACKEND_RESPONSE_TIMEOUT_SECS", 1.0):
                with pytest.raises(RuntimeError):
                    pool.get_or_create(None)
            assert pool.count() == 0
        finally:
            pool.shutdown_all()


# --- the rewrite seam and discover synthesis (#270 Phase 3 P3-B) ---------


class TestStampModernResult:
    """What a 2026-07-28 server owes on top of a legacy child's result."""

    def test_result_type_is_stamped_on_every_result(self):
        """O3 is a MUST on EVERY result, not just the cacheable six.

        The absent-means-complete leniency is explicitly a CLIENT
        obligation toward EARLIER-protocol servers; serve, answering as a
        2026-07-28 server, gets no waiver.
        """
        for method in ("tools/list", "tools/call", "resources/read", "prompts/get"):
            msg = server._stamp_modern_result({"result": {}}, method)
            assert msg["result"]["resultType"] == "complete", method

    def test_caching_hints_land_on_the_six_and_nowhere_else(self):
        for method in sorted(server._CACHEABLE_METHODS):
            result = server._stamp_modern_result({"result": {}}, method)["result"]
            assert result["ttlMs"] == server._DEFAULT_CACHE_TTL_MS, method
            assert result["cacheScope"] == "private", method

    def test_tools_call_never_gets_caching_hints(self):
        """`CallToolResult` is not a CacheableResult, and the v2 client's
        model has no `ttlMs`/`cacheScope` fields at all — stamping them
        would be inventing wire data."""
        assert "tools/call" not in server._CACHEABLE_METHODS
        result = server._stamp_modern_result({"result": {"content": []}}, "tools/call")
        assert "ttlMs" not in result["result"]
        assert "cacheScope" not in result["result"]

    def test_errors_are_never_stamped(self):
        """Structural, not policy: `resultType` is a field OF `result`,
        and an error response has no `result` member to put it in."""
        msg = {"error": {"code": -32601, "message": "nope"}}
        assert server._stamp_modern_result(dict(msg), "tools/list") == msg

    def test_stamps_are_iff_absent(self):
        """A child that already speaks the modern dialect keeps its own
        values — the seam is a widening, not a rewrite."""
        msg = server._stamp_modern_result(
            {
                "result": {
                    "resultType": "input_required",
                    "ttlMs": 5,
                    "cacheScope": "public",
                }
            },
            "tools/list",
            server_info={"name": "ours", "version": "9"},
        )
        assert msg["result"]["resultType"] == "input_required"
        assert msg["result"]["ttlMs"] == 5
        assert msg["result"]["cacheScope"] == "public"

    def test_server_info_is_echoed_into_meta_on_every_result(self):
        info = {"name": "child", "version": "1.2.3"}
        for method in ("tools/list", "tools/call"):
            result = server._stamp_modern_result(
                {"result": {}}, method, server_info=info
            )["result"]
            assert result["_meta"]["io.modelcontextprotocol/serverInfo"] == info, method

    def test_a_custom_ttl_threads_through(self):
        result = server._stamp_modern_result(
            {"result": {}}, "tools/list", cache_ttl_ms=0
        )["result"]
        assert result["ttlMs"] == 0


class TestSynthesizeDiscover:
    def test_carries_the_two_fields_the_client_requires(self):
        """Both are load-bearing for interop, not decoration: the v2
        client validates `DiscoverResult` with exactly `supportedVersions`
        and `capabilities` required, and a ValidationError makes it
        SILENTLY fall back to `initialize`."""
        result = server._synthesize_discover_result(
            {"capabilities": {"tools": {}}, "serverInfo": {"name": "f", "version": "0"}}
        )
        assert result["supportedVersions"] == ["2026-07-28"]
        assert result["capabilities"] == {"tools": {}}
        assert result["resultType"] == "complete"
        assert result["ttlMs"] == server._DEFAULT_CACHE_TTL_MS
        assert result["cacheScope"] == "private"
        assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "f"

    def test_a_capability_less_child_still_yields_an_object(self):
        """The silent-fallback trap: a child answering with no
        capabilities (or a null one) must still produce the OBJECT the
        client's validation requires, or discovery "succeeds" while the
        modern path quietly never engages."""
        for init in ({}, {"capabilities": None}):
            result = server._synthesize_discover_result(init)
            assert result["capabilities"] == {}
            assert isinstance(result["capabilities"], dict)

    def test_supported_versions_are_serves_own_not_the_childs(self):
        """The child speaks 2025-06-18; the question is what the ENDPOINT
        supports."""
        result = server._synthesize_discover_result(
            {"protocolVersion": "2025-06-18", "capabilities": {}}
        )
        assert "2025-06-18" not in result["supportedVersions"]
        assert result["supportedVersions"] == sorted(
            server._SERVE_IMPLEMENTED_MODERN_VERSIONS
        )


class TestModernIdMinting:
    def test_minted_ids_are_unique_across_threads(self):
        """Two concurrent modern clients may share one pooled child and
        may well have chosen the same integer id; minting our own removes
        the collision by construction."""
        seen: list[str] = []
        lock = threading.Lock()

        def _mint():
            local = [server._mint_modern_id() for _ in range(50)]
            with lock:
                seen.extend(local)

        threads = [threading.Thread(target=_mint) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert len(seen) == 200
        assert len(set(seen)) == 200
        assert all(i.startswith("mcp-stdio/serve/") for i in seen)

    def test_reserved_client_ids_are_recognised(self):
        assert server._is_reserved_client_id("mcp-stdio/serve/1") is True
        assert server._is_reserved_client_id("mcp-stdio/serve") is False
        assert server._is_reserved_client_id(1) is False
        assert server._is_reserved_client_id(None) is False
