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
import time

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


def _assert_reached_dispatch(resp: httpx.Response, req_id: object = 1) -> dict:
    """The request PASSED the ladder and was answered by the modern path.

    P3-A used the legacy sessionless `-32000` as this signal, because a
    validated modern request fell through to the session code. P3-B's
    seam flip replaced that fallthrough with dispatch, so the signal is
    now "answered by the gateway or the child, and NOT by a ladder rung".

    Still no `Mcp-Session-Id`: the modern branch never sets
    `self._session_id`, so `_send_json`'s auto-echo has nothing to echo —
    asserted on SUCCESSES here, not only on rejections.
    """
    # STATUS is the discriminator, not the error code: every ladder
    # rejection is a 400, while a dispatched response is 200 (or 404 for
    # an unimplemented method). The code cannot discriminate — a child's
    # own "unknown tool" is legitimately -32602, the same code the ladder
    # uses for a malformed `_meta`.
    assert resp.status_code in (200, 404), (resp.status_code, resp.text)
    body = resp.json()
    assert body["id"] == req_id, body
    assert "mcp-session-id" not in resp.headers, dict(resp.headers)
    return body


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
        _assert_reached_dispatch(_post(gateway, body, _modern_headers()))


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
        _assert_reached_dispatch(_post(gateway, body, headers))

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
        # The fake child does not implement `resources/read`, so it
        # answers -32601 and serve maps that to HTTP 404 per the spec's
        # "MUST respond with 404 Not Found" — the same carve-out
        # `subscriptions/listen` relies on until 3.5-D.
        passed = _post(gateway, body, ok)
        assert passed.status_code == 404
        _assert_reached_dispatch(passed)
        bad = _modern_headers("resources/read", name="file:///b.txt")
        _assert_rejected(_post(gateway, body, bad), HEADER_MISMATCH)

    def test_non_name_bearing_method_needs_no_name_header(self, gateway):
        body = _modern_body("tools/list", meta=_meta())
        _assert_reached_dispatch(_post(gateway, body, _modern_headers()))

    def test_name_bearing_method_with_no_body_value_skips_the_check(self, gateway):
        """Deliberate hole, pinned so it reads as a decision.

        A `tools/call` with no `params` at all has no body value for
        `Mcp-Name` to mirror, so rung 2c is SKIPPED and the request falls
        through. Dispatch owns missing-param errors; inventing a header
        mismatch for a body problem would report the wrong fault.
        """
        body = _modern_body("tools/call", meta=_meta())
        _assert_reached_dispatch(_post(gateway, body, _modern_headers("tools/call")))

    def test_unknown_mcp_param_headers_are_ignored(self, gateway):
        """Spec: an intermediary "MUST forward it and otherwise ignore
        it". P3-A forwards nothing yet; the obligation here is only that
        an unknown one does not reject."""
        headers = _modern_headers()
        headers["Mcp-Param-Foo"] = "anything"
        body = _modern_body(meta=_meta())
        _assert_reached_dispatch(_post(gateway, body, headers))

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


class TestModernDispatch:
    """What a modern request gets now that the seam is flipped (P3-B)."""

    def test_modern_notification_is_forwarded_and_acknowledged(self, gateway):
        """202 with no body, sessionless — §4 Q4 adopted.

        P3-A left modern notifications on the legacy fallthrough, where a
        SESSIONLESS one earned a 400 because session resolution ran
        first. They now take the modern branch like everything else:
        forwarded to the pooled child, acknowledged 202. The v2 client
        sends none in the discover flow (no `initialize` means no
        `notifications/initialized`), so this is consistency rather than
        liveness — but leaving modern-classified traffic on a legacy
        session error would be a worse answer than 202.

        Still no header rungs: a notification carries no headers here at
        all, and the ladder is a full no-op for it (O9).
        """
        body = _modern_body(
            "notifications/initialized", meta=_meta(), notification=True
        )
        resp = _post(gateway, body)
        assert resp.status_code == 202
        assert resp.content == b""
        assert "mcp-session-id" not in resp.headers

    def test_a_valid_modern_request_is_dispatched_statelessly(self, gateway):
        """**AC1's unit-level core**: no initialize, no session, a result.

        This is the assertion P3-A could not make. Its version of this
        test asserted the 400 `-32000` fallthrough and was labelled "P3-A
        ships ZERO modern dispatch"; the flip is precisely what changes
        it, so the diff here IS the deliverable.

        Spec: "Servers MUST NOT rely on prior requests over the same
        connection to establish context." Nothing preceded this request.
        """
        body = _modern_body("tools/list", meta=_meta())
        resp = _post(gateway, body, _modern_headers())
        assert resp.status_code == 200
        result = resp.json()["result"]
        assert [t["name"] for t in result["tools"]] == ["echo_tool"]
        # Stamped on the way out, asserted on the RAW wire.
        assert result["resultType"] == "complete"
        assert result["ttlMs"] == server._DEFAULT_CACHE_TTL_MS
        assert result["cacheScope"] == "private"
        assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "fake"
        assert "mcp-session-id" not in resp.headers

    def test_tools_call_round_trips_without_caching_hints(self, gateway):
        body = _modern_body(
            "tools/call",
            params={"name": "echo_tool", "arguments": {"text": "hi"}},
            meta=_meta(),
        )
        headers = _modern_headers("tools/call", name="echo_tool")
        resp = _post(gateway, body, headers)
        assert resp.status_code == 200
        result = resp.json()["result"]
        assert json.loads(result["content"][0]["text"]) == {"text": "hi"}
        assert result["resultType"] == "complete"
        # `CallToolResult` is not a CacheableResult — the v2 client's model
        # has no such fields, so stamping them would invent wire data.
        assert "ttlMs" not in result and "cacheScope" not in result

    def test_discover_is_answered_by_serve_not_the_child(self, gateway):
        """The child has never heard of `server/discover` and would answer
        -32601; serve owns the answer, sourced from the handshake it
        performed on the client's behalf."""
        body = _modern_body("server/discover", meta=_meta())
        resp = _post(gateway, body, _modern_headers("server/discover"))
        assert resp.status_code == 200
        result = resp.json()["result"]
        # The two fields the v2 client REQUIRES. Missing either makes it
        # silently fall back to `initialize` — discovery "succeeds" while
        # the modern path never engages.
        assert result["supportedVersions"] == ["2026-07-28"]
        assert isinstance(result["capabilities"], dict)
        assert result["resultType"] == "complete"
        assert result["ttlMs"] == server._DEFAULT_CACHE_TTL_MS
        assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "fake"

    def test_a_legacy_session_id_on_a_modern_request_is_ignored(self, gateway):
        """P3-A interim, closed. The header names a REAL session here, and
        the modern request must still be served by the POOL — not by that
        session's child — and must echo no session id back."""
        init = _post(gateway, {"jsonrpc": "2.0", "id": "i", "method": "initialize"})
        sid = init.headers["mcp-session-id"]
        assert sid

        body = _modern_body("tools/list", meta=_meta())
        resp = _post(gateway, body, {**_modern_headers(), "Mcp-Session-Id": sid})
        assert resp.status_code == 200
        assert "mcp-session-id" not in resp.headers
        assert resp.json()["result"]["resultType"] == "complete"

    def test_a_client_id_in_serves_namespace_is_rejected(self, gateway):
        """Closes by construction the gap relay's PR C closed by rule: an
        id indistinguishable from serve's own bookkeeping is refused where
        it ENTERS, not disambiguated at every later consumer."""
        body = _modern_body("tools/list", req_id="mcp-stdio/serve/1", meta=_meta())
        resp = _post(gateway, body, _modern_headers())
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == -32600
        assert resp.json()["id"] == "mcp-stdio/serve/1"

    def test_an_unimplemented_method_comes_back_404(self, gateway):
        """Spec: an unimplemented method "MUST respond with 404 Not Found"
        and -32601. Also the carve-out `subscriptions/listen` needs until
        3.5-D — the client must not read it as a malformed 200."""
        body = _modern_body("subscriptions/listen", meta=_meta())
        resp = _post(gateway, body, _modern_headers("subscriptions/listen"))
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == -32601

    def test_errors_from_the_child_are_never_stamped(self, gateway):
        """Structural: `resultType` is a field OF `result`, and an error
        response has no `result` member to carry it."""
        body = _modern_body(
            "tools/call", params={"name": "nope", "arguments": {}}, meta=_meta()
        )
        resp = _post(gateway, body, _modern_headers("tools/call", name="nope"))
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["error"]["code"] == -32602
        assert "result" not in payload

    def test_a_child_initiated_request_is_rejected_not_queued(self, gateway):
        """The reject arm, end to end.

        A gateway-owned child has no stream and no consumer, so a
        child-initiated request would otherwise sit in `server_initiated`
        forever while the child blocks on a reply. It is answered from the
        reader thread instead — which also discharges O15, since nothing
        of the kind ever reaches a stream because there is none.
        """
        body = _modern_body("ask_client", meta=_meta())
        resp = _post(gateway, body, _modern_headers("ask_client"))
        assert resp.status_code == 200
        assert resp.json()["result"]["asked"] is True


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


def _checkout_and_release(pool, principal=None):
    """Acquire a pooled child the way a handler does, then hand it back.

    `get_or_create` returns a CHECKED-OUT child (#376 §3.1) whose hold
    must be released, or it stays permanently unevictable. Tests that
    only want "the child for this principal" go through here so they
    exercise the same acquire/release pair `_dispatch_modern` does;
    tests that specifically want a HELD child call `get_or_create`
    directly and keep the entry.
    """
    backend, init_result, entry = pool.get_or_create(principal)
    pool.release(entry)
    return backend, init_result


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
            backend, init_result = _checkout_and_release(pool, None)
            assert init_result["protocolVersion"] == "2025-06-18"
            assert init_result["serverInfo"]["name"] == "fake"
            # A second call reuses the same child rather than respawning.
            again, cached = _checkout_and_release(pool, None)
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
            alice, _ = _checkout_and_release(pool, "alice")
            bob, _ = _checkout_and_release(pool, "bob")
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
            got.append(_checkout_and_release(pool, "shared")[0])

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
            first, _ = _checkout_and_release(pool, None)
            first.shutdown()
            assert first.closed
            second, _ = _checkout_and_release(pool, None)
            assert second is not first
            assert not second.closed
        finally:
            pool.shutdown_all()

    def test_a_dead_child_is_reaped_when_get_or_create_drops_it(self):
        """#373 review, /code-review score 100: the child-died branch used
        to pop the dead entry and loop to respawn WITHOUT ever reaping the
        popped backend — every OTHER cleanup path here (eviction, a failed
        spawn, `shutdown_all`) already calls `shutdown()` on a leaving
        child, and the legacy dead-session mirror's own comment says why:
        "shutdown() reaps the already-exited child". Skipping it here
        leaked a zombie process on every pooled-child crash.

        The child exits ON ITS OWN (`exit`, no reply expected) rather than
        via `first.shutdown()` — calling `shutdown()` directly would reap
        it itself and prove nothing about `get_or_create()`.
        """
        pool = server.ModernBackendPool(_BACKEND)
        try:
            first, _ = _checkout_and_release(pool, None)
            first.send_oneway(json.dumps({"jsonrpc": "2.0", "method": "exit"}))
            deadline = time.monotonic() + 10
            while not first.closed and time.monotonic() < deadline:
                time.sleep(0.01)
            assert first.closed, "the child never closed"
            # Not yet reaped: nothing but shutdown()/poll()/wait() collects
            # the exit status, and nothing has called any of them yet.
            assert first._proc.returncode is None, (
                "the child was reaped before get_or_create() ever ran"
            )

            second, _ = _checkout_and_release(pool, None)

            assert second is not first
            assert first._proc.returncode is not None, (
                "get_or_create() dropped the dead child without reaping it"
            )
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
            _checkout_and_release(pool, "a")
            _checkout_and_release(pool, "b")
            assert pool.count() == 2
            _checkout_and_release(pool, "c")
            assert pool.count() == 2, "the cap did not hold"
        finally:
            pool.shutdown_all()

    def test_eviction_never_takes_a_pending_or_busy_child(self):
        """#373 review R1F1 — the cap must bound processes, not leak them.

        Two ways the naive "evict the smallest `used`" loses:

        - a PENDING entry has no backend yet and no `used`, so it sorted
          FIRST. Evicting it detaches the entry the spawning thread is
          about to fill, and that child then belongs to nobody —
          `shutdown_all()` cannot reach it, so the cap would leak
          processes rather than bound them;
        - `used` is last-ACQUIRED time, not in-flight work, so the
          "idlest" child can still have a request on the wire. Shutting
          it down fails an ordinary concurrent request to make room.

        When nothing qualifies the cap is EXCEEDED rather than enforced —
        the right way to fail for a soft resource policy whose only
        alternative is breaking work already in flight.
        """
        pool = server.ModernBackendPool(_BACKEND, max_children=1)
        try:
            busy, _ = _checkout_and_release(pool, "busy")
            # Park a request on the child so it is provably not idle.
            started = threading.Event()
            done = threading.Event()

            def _occupy():
                started.set()
                busy.send_request(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": "slow",
                            "method": "slow_echo",
                            "params": {"delay": 2.0},
                        }
                    ),
                    "slow",
                    30.0,
                )
                done.set()

            worker = threading.Thread(target=_occupy, daemon=True)
            worker.start()
            assert started.wait(timeout=10)
            deadline = time.monotonic() + 10
            while not busy.has_pending and time.monotonic() < deadline:
                time.sleep(0.01)
            assert busy.has_pending, "the request never reached the child"

            # At cap, with the only child busy: the newcomer is served and
            # the busy child is NOT killed.
            other, _ = _checkout_and_release(pool, "other")
            assert other is not busy
            assert not busy.closed, "eviction killed a child mid-request"
            assert pool.count() == 2, "the cap was enforced by breaking live work"
            assert done.wait(timeout=30)
        finally:
            pool.shutdown_all()

    def test_a_checked_out_child_is_not_evicted_at_cap(self):
        """#376 §3.1 — the eviction-vs-send race, closed by refcount.

        `get_or_create` returns with the pool lock released, and the
        request only becomes `has_pending` later, inside the BACKEND's
        lock. In that window the child looks perfectly idle, so another
        principal's first request at cap could evict a child that was
        already handed to a handler — which shut it down under the
        caller and produced a spurious 504.

        The checkout refcount closes it by construction: the child is
        held from the moment it is returned. Reverting the `holds` clause
        of `_reapable_locked` makes this evict.
        """
        pool = server.ModernBackendPool(_BACKEND, max_children=1)
        try:
            held, _, entry = pool.get_or_create("first")
            assert entry["holds"] == 1
            # Not yet sending: the window the race lives in.
            assert not held.has_pending

            other, _ = _checkout_and_release(pool, "second")
            assert other is not held
            assert not held.closed, "a checked-out child was evicted mid-window"
            assert pool.count() == 2, "the cap was enforced against a held child"
        finally:
            pool.shutdown_all()

    def test_releasing_makes_the_child_evictable_again(self):
        """A hold is a loan, not a pin — the other half of the contract."""
        pool = server.ModernBackendPool(_BACKEND, max_children=1)
        try:
            held, _, entry = pool.get_or_create("first")
            pool.release(entry)
            assert entry["holds"] == 0
            _checkout_and_release(pool, "second")
            assert pool.count() == 1, "a released child stayed unevictable"
            assert held.closed
        finally:
            pool.shutdown_all()

    def test_release_never_drives_the_count_negative(self):
        """An extra release must not lend the next caller a free pass."""
        pool = server.ModernBackendPool(_BACKEND)
        try:
            _, _, entry = pool.get_or_create(None)
            pool.release(entry)
            pool.release(entry)
            assert entry["holds"] == 0
        finally:
            pool.shutdown_all()

    def test_the_cap_is_rebounded_after_a_spawn_race(self):
        """#376 §3.2 — an overshoot that used to be permanent.

        Racing first-requests each insert a PENDING placeholder, and a
        placeholder is not evictable, so once the ready-quiet victims run
        out every racer logs "exceeding the cap" and inserts anyway.
        Nothing re-bounded that afterwards: the overshoot persisted until
        the next NEW principal arrived — in a two-principal deployment,
        never.

        Both racers first park with their placeholders in the map, which
        is what establishes the overshoot. They are then released ONE AT
        A TIME, and that ordering is deliberate rather than incidental:
        the second racer's post-spawn sweep can only reclaim the first
        child once it is quiet AND released, so gating on that makes the
        outcome deterministic instead of a race the CI host wins or loses
        (it lost on Windows, where the slower spawn let both children be
        held at once).

        Revert-check: without the post-spawn `_evict_if_at_cap_locked`
        the count stays at 2.
        """
        pool = server.ModernBackendPool(_BACKEND, max_children=1)
        both_pending = threading.Barrier(3)
        gates = {"alice": threading.Event(), "bob": threading.Event()}
        done = {"alice": threading.Event(), "bob": threading.Event()}
        current = threading.local()
        real_spawn = pool._spawn_and_handshake

        def _gated_spawn():
            # Both racers park here, so both placeholders coexist — the
            # state that produces the overshoot.
            both_pending.wait(timeout=15)
            assert gates[current.principal].wait(timeout=15)
            return real_spawn()

        pool._spawn_and_handshake = _gated_spawn

        def _racer(principal):
            current.principal = principal
            backend, _, entry = pool.get_or_create(principal)
            pool.release(entry)
            done[principal].set()

        threads = [
            threading.Thread(target=_racer, args=(name,), daemon=True)
            for name in ("alice", "bob")
        ]
        try:
            for t in threads:
                t.start()
            both_pending.wait(timeout=15)
            assert pool.count() == 2, "the racers did not both hold a placeholder"

            # Alice finishes and releases. Her own sweep finds nothing to
            # take (bob is still PENDING), so the pool stays over cap.
            gates["alice"].set()
            assert done["alice"].wait(timeout=30)
            assert pool.count() == 2, "alice's sweep should have found no victim"

            # Bob finishes. His sweep now finds alice ready, quiet and
            # unheld — the overshoot is reclaimed.
            gates["bob"].set()
            assert done["bob"].wait(timeout=30)
            assert pool.count() == 1, "the spawn-race overshoot was never re-bounded"
        finally:
            pool._spawn_and_handshake = real_spawn
            for gate in gates.values():
                gate.set()
            for t in threads:
                t.join(timeout=30)
            pool.shutdown_all()

    def test_reaching_the_cap_does_not_evict(self):
        """At the cap is not over it — the off-by-one guard.

        `_evict_if_at_cap_locked` means "make room for one more", so the
        pre-insert callers pass `reserve=1`. The post-spawn re-check
        (#376 §3.2) has already inserted; with the same reserve it would
        evict a child every time the pool merely REACHED the cap. With
        `max_children=2`, two principals must both survive.
        """
        pool = server.ModernBackendPool(_BACKEND, max_children=2)
        try:
            first, _ = _checkout_and_release(pool, "a")
            second, _ = _checkout_and_release(pool, "b")
            assert pool.count() == 2, "reaching the cap evicted a child"
            assert not first.closed and not second.closed
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

    def test_notification_dependent_flags_are_stripped(self):
        """#373 review, /code-review score 85: discover cannot honor
        `tools.listChanged`, `resources.subscribe`, `resources.listChanged`
        or `prompts.listChanged` until 3.5-D ships `subscriptions/listen` —
        `_queue_server_initiated`'s modern_owned branch silently discards
        every notification a pooled child sends today. Echoing these flags
        verbatim would advertise a promise this endpoint cannot keep.
        """
        result = server._synthesize_discover_result(
            {
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"subscribe": True, "listChanged": True},
                    "prompts": {"listChanged": True},
                    "completions": {},
                }
            }
        )
        caps = result["capabilities"]
        assert "listChanged" not in caps["tools"]
        assert "subscribe" not in caps["resources"]
        assert "listChanged" not in caps["resources"]
        assert "listChanged" not in caps["prompts"]
        # The family objects survive — the REQUEST surfaces (tools/list,
        # resources/read, prompts/get) are served today — just emptied of
        # the stripped keys, never removed wholesale.
        assert "tools" in caps
        assert "resources" in caps
        assert "prompts" in caps
        # Control: a non-notification-dependent capability passes through
        # untouched, proving the filter is scoped to the four flags rather
        # than over-stripping.
        assert caps["completions"] == {}

    def test_a_non_stripped_key_survives_within_a_stripped_family(self):
        """The filter removes specific KEYS, never the whole family
        object: a hypothetical `resources.other` flag must survive
        alongside `subscribe` being stripped from the SAME family — spec
        capability semantics are presence-based per key, not per family."""
        result = server._synthesize_discover_result(
            {"capabilities": {"resources": {"subscribe": True, "other": "x"}}}
        )
        assert result["capabilities"]["resources"] == {"other": "x"}

    def test_malformed_capabilities_degrades_instead_of_crashing(self):
        """#373 review R3F1: a misbehaving child answering `initialize`
        with a truthy NON-dict `capabilities` (e.g. `"capabilities":
        "tools"`) used to crash `_strip_undeliverable_capability_flags`'s
        `.items()` call with an uncaught `AttributeError` — aborting the
        whole discover HTTP request instead of degrading, where the RAW
        echo (before this fix's stripping existed) degraded gracefully on
        the client side (a spec-tolerable `ValidationError` -> silent
        fallback to `initialize`). `capabilities` stays present — still
        the DiscoverResult's REQUIRED object — but empty: a malformed
        child forfeits capability advertisement, never the request."""
        result = server._synthesize_discover_result({"capabilities": "tools"})
        assert result["capabilities"] == {}
        assert result["resultType"] == "complete"

    def test_a_non_dict_family_value_passes_through_unstripped(self):
        """A well-formed top-level dict whose FAMILY value is itself
        malformed (e.g. `"tools": true`, spec-invalid) must not crash
        either — only a dict family has keys to strip from, so it passes
        through as-is, while a sibling well-formed family is still
        stripped normally."""
        result = server._synthesize_discover_result(
            {"capabilities": {"tools": True, "resources": {"subscribe": True}}}
        )
        caps = result["capabilities"]
        assert caps["tools"] is True
        assert caps["resources"] == {}


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


def test_a_pooled_child_never_fills_the_unread_sse_queue():
    """#373 review R1F2 — every server-initiated path sheds, not just two.

    A gateway-owned child has no SSE stream and no consumer, so anything
    put on `server_initiated` is retained for the life of the process.
    The child-request and notification arms were gated; the
    `kind == "response"` arm has its OWN put for a response whose waiter
    is gone, and repeated backend timeouts would grow that without bound.

    Driven through the real reader thread by feeding it lines directly:
    an orphan RESPONSE (no waiter), a notification, and unparseable
    noise — the three sources — must all leave the queue empty.
    """
    pool = server.ModernBackendPool(_BACKEND)
    try:
        backend, _ = _checkout_and_release(pool, None)
        assert backend.server_initiated.qsize() == 0
        backend._route('{"jsonrpc":"2.0","id":"nobody-waits","result":{}}')
        backend._route('{"jsonrpc":"2.0","method":"notifications/message"}')
        backend._route("this is not json at all")
        assert backend.server_initiated.qsize() == 0, "a pooled child filled the queue"
    finally:
        pool.shutdown_all()


def test_a_legacy_child_still_queues_server_initiated_traffic():
    """The other half of R1F2's gate: legacy behavior is byte-identical.

    The SSE stream is a real consumer there, so shedding would be a
    regression — `test_server.py`'s push test depends on it.
    """
    backend = server.BackendProcess(_BACKEND)
    try:
        backend._route('{"jsonrpc":"2.0","method":"notifications/message"}')
        backend._route('{"jsonrpc":"2.0","id":"nobody-waits","result":{}}')
        assert backend.server_initiated.qsize() == 2
    finally:
        backend.shutdown()


class TestModernPoolReaper:
    """Idle eviction for pooled children (#376 §2).

    A fake clock throughout — the reaper's only time input is the
    injected `now`, so nothing here waits on wall time.
    """

    def _pool(self, clock, **kw):
        return server.ModernBackendPool(
            _BACKEND, idle_ttl=kw.pop("idle_ttl", 30.0), now=lambda: clock[0], **kw
        )

    def test_a_child_is_kept_until_the_ttl_elapses(self):
        clock = [1000.0]
        pool = self._pool(clock)
        try:
            _checkout_and_release(pool)
            clock[0] += 29.0
            assert pool.reap_idle() == 0
            assert pool.count() == 1
        finally:
            pool.shutdown_all()

    def test_a_child_idle_past_the_ttl_is_reaped(self):
        clock = [1000.0]
        pool = self._pool(clock)
        try:
            backend, _ = _checkout_and_release(pool)
            clock[0] += 31.0
            assert pool.reap_idle() == 1
            assert pool.count() == 0
            # Shutdown runs on a daemon thread, so observe the outcome
            # rather than assuming it already happened.
            deadline = time.monotonic() + 10
            while not backend.closed and time.monotonic() < deadline:
                time.sleep(0.01)
            assert backend.closed
        finally:
            pool.shutdown_all()

    def test_a_request_on_the_wire_protects_an_old_child(self):
        """`used` is last-ACQUIRED time, so a long call looks idle by it."""
        clock = [1000.0]
        pool = self._pool(clock)
        try:
            backend, _ = _checkout_and_release(pool)
            started = threading.Event()

            def _occupy():
                started.set()
                backend.send_request(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": "slow",
                            "method": "slow_echo",
                            "params": {"delay": 2.0},
                        }
                    ),
                    "slow",
                    30.0,
                )

            worker = threading.Thread(target=_occupy, daemon=True)
            worker.start()
            assert started.wait(timeout=10)
            deadline = time.monotonic() + 10
            while not backend.has_pending and time.monotonic() < deadline:
                time.sleep(0.01)
            assert backend.has_pending

            clock[0] += 31.0
            assert pool.reap_idle() == 0, "reaped a child with a request on the wire"
            worker.join(timeout=30)
        finally:
            pool.shutdown_all()

    def test_a_held_child_is_never_reaped(self):
        """The #374 seam: a hold outranks any timestamp.

        This is the case a TTL alone cannot express — a listen stream may
        sit subscribed for hours without the child being 'used'.
        """
        clock = [1000.0]
        pool = self._pool(clock)
        try:
            _, _, entry = pool.get_or_create(None)  # held, never released
            clock[0] += 3600.0
            assert pool.reap_idle() == 0, "reaped a child that was checked out"
            assert pool.count() == 1
            pool.release(entry)
            assert pool.reap_idle() == 1
        finally:
            pool.shutdown_all()

    def test_a_pending_placeholder_is_never_reaped(self):
        clock = [1000.0]
        pool = self._pool(clock)
        try:
            with pool._lock:
                pool._entries["ghost"] = {
                    "event": threading.Event(),
                    "backend": None,
                    "error": None,
                    "holds": 0,
                }
            clock[0] += 3600.0
            assert pool.reap_idle() == 0
            assert pool.count() == 1
        finally:
            with pool._lock:
                pool._entries.pop("ghost", None)
            pool.shutdown_all()

    def test_a_dead_child_is_reaped_even_with_the_ttl_disabled(self):
        """Otherwise a departed principal's zombie pins a slot forever —
        the lazy cleanup only fires on that principal's next request."""
        clock = [1000.0]
        pool = self._pool(clock, idle_ttl=0.0)
        try:
            backend, _ = _checkout_and_release(pool)
            backend.shutdown()
            assert backend.closed
            assert pool.reap_idle() == 1
            assert pool.count() == 0
        finally:
            pool.shutdown_all()

    def test_the_reaper_thread_only_starts_when_the_ttl_is_set(self):
        clock = [1000.0]
        off = self._pool(clock, idle_ttl=0.0)
        try:
            off.start_reaper()
            assert not any(
                t.name == "modern-pool-reaper" for t in threading.enumerate()
            )
        finally:
            off.shutdown_all()

        on = self._pool(clock, idle_ttl=30.0)
        try:
            on.start_reaper()
            assert any(t.name == "modern-pool-reaper" for t in threading.enumerate())
        finally:
            on.shutdown_all()
        # shutdown_all stops it; the daemon exits on its next tick.
        assert on._reaper is None


def test_build_server_threads_the_modern_idle_ttl_through():
    httpd, registry = server.build_server(
        _BACKEND, host="127.0.0.1", port=0, modern_idle_ttl=45.0
    )
    try:
        assert httpd.modern_pool._idle_ttl == 45.0
    finally:
        registry.shutdown_all()
        httpd.modern_pool.shutdown_all()
        httpd.server_close()


class TestModernOnly:
    """The `--modern-only` posture (#376 §4).

    The era predicate is untouched — the flag acts AFTER classification,
    so modern traffic is byte-identical with it on or off.
    """

    @pytest.fixture()
    def strict(self):
        httpd, registry = server.build_server(
            _BACKEND, host="127.0.0.1", port=0, modern_only=True
        )
        host, port = httpd.server_address[0], httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://{host}:{port}/mcp"
        finally:
            httpd.shutdown()
            registry.shutdown_all()
            httpd.modern_pool.shutdown_all()
            httpd.server_close()

    def test_get_is_405_with_an_allow_header(self, strict):
        """RFC 9110 §15.5.6 requires `Allow` on a 405 — that requirement
        is HTTP's, not MCP's, so it holds whatever the body says."""
        resp = httpx.get(strict, timeout=10)
        assert resp.status_code == 405
        assert resp.headers["allow"] == "POST"
        assert resp.json()["error"]["code"] == -32600

    def test_delete_is_405_with_an_allow_header(self, strict):
        resp = httpx.request("DELETE", strict, timeout=10)
        assert resp.status_code == 405
        assert resp.headers["allow"] == "POST"

    def test_a_legacy_initialize_is_refused_with_the_supported_versions(self, strict):
        """-32022 is actionable where a bare 400 is not: an
        auto-negotiating client reads `data.supported` and retries."""
        resp = _post(strict, {"jsonrpc": "2.0", "id": "init", "method": "initialize"})
        assert resp.status_code == 400
        error = resp.json()["error"]
        assert error["code"] == -32022
        assert error["data"]["supported"] == [MODERN_VERSION]
        assert resp.json()["id"] == "init"
        assert "mcp-session-id" not in resp.headers

    def test_other_legacy_posts_take_the_untouched_sessionless_path(self, strict):
        """With initialize refused no session can exist, so everything
        else already dies on the existing path — the flag adds no second
        rejection for it."""
        resp = _post(strict, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == LEGACY_ERROR

    def test_modern_traffic_is_unaffected(self, strict):
        discover = _post(
            strict,
            _modern_body("server/discover", meta=_meta()),
            _modern_headers("server/discover"),
        )
        assert discover.status_code == 200
        assert discover.json()["result"]["supportedVersions"] == [MODERN_VERSION]

        listed = _post(strict, _modern_body(meta=_meta()), _modern_headers())
        assert listed.status_code == 200
        assert listed.json()["result"]["resultType"] == "complete"

    def test_the_flag_defaults_off(self, gateway):
        """The unit-level twin of the pin suite — NOT an edit to it.

        With the flag unset, GET and DELETE behave exactly as they always
        have: a sessionless GET is 400 (not 405), and DELETE likewise.
        """
        get = httpx.get(gateway, timeout=10)
        assert get.status_code == 400
        assert "allow" not in get.headers
        delete = httpx.request("DELETE", gateway, timeout=10)
        assert delete.status_code == 400

        init = _post(gateway, {"jsonrpc": "2.0", "id": "i", "method": "initialize"})
        assert init.status_code == 200
        assert init.headers.get("mcp-session-id")


def test_modern_only_keeps_the_oauth_discovery_endpoints_reachable():
    """The carve-out: PRM and AS metadata are HTTP plumbing, not MCP
    transport, and a modern-only deployment still needs them to bootstrap
    OAuth. They are routed before the 405."""
    provider = server._OAuthProvider(
        public_url=None, trusted_user_header=None, dev_user="alice"
    )
    httpd, registry = server.build_server(
        _BACKEND, host="127.0.0.1", port=0, modern_only=True, oauth=provider
    )
    host, port = httpd.server_address[0], httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://{host}:{port}"
    try:
        prm = httpx.get(f"{base}/.well-known/oauth-protected-resource/mcp", timeout=10)
        assert prm.status_code == 200, prm.text
        as_meta = httpx.get(
            f"{base}/.well-known/oauth-authorization-server", timeout=10
        )
        assert as_meta.status_code == 200, as_meta.text
    finally:
        httpd.shutdown()
        registry.shutdown_all()
        httpd.modern_pool.shutdown_all()
        httpd.server_close()


def test_serve_main_threads_both_new_flags_through():
    """Both knobs have to survive `serve_main` -> `serve`, and neither has
    a runtime effect a parse test would otherwise notice."""
    seen: dict = {}

    def _fake_serve(command, **kwargs):
        seen.update(kwargs)

    with patch.object(server, "serve", _fake_serve):
        server.serve_main(
            ["--modern-only", "--modern-idle-ttl", "45", "--", "python", "-c", "pass"]
        )
    assert seen["modern_only"] is True
    assert seen["modern_idle_ttl"] == 45.0

    seen.clear()
    with patch.object(server, "serve", _fake_serve):
        server.serve_main(["--", "python", "-c", "pass"])
    assert seen["modern_only"] is False
    assert seen["modern_idle_ttl"] == 0.0


def test_a_negative_modern_idle_ttl_is_rejected():
    with pytest.raises(SystemExit):
        server.serve_main(["--modern-idle-ttl", "-1", "--", "python", "-c", "pass"])


def test_a_newborn_child_is_published_atomically():
    """#379 review R1F1 — a newborn must never be visible unheld.

    Publication used to assign `entry["backend"]` before `entry["used"]`
    and take the hold later still. A reaper landing in that gap saw a
    READY, quiet, unheld entry whose `used` defaulted to 0.0 — a child
    apparently idle since the epoch — popped it, and shut down the very
    backend `get_or_create` was about to return. The caller's first
    request then hit a corpse and came back 504.

    Asserted structurally rather than by winning a race: the pool lock is
    not reentrant, so `acquire(blocking=False)` from the publishing
    thread tells us whether that thread already holds it. `_now()` is
    called exactly where `used` is set, so probing there answers "was
    publication inside the lock?" deterministically.

    Revert-check: move the assignments back outside the `with` and the
    probe records False.
    """
    observations: list[bool] = []
    clock = [1000.0]

    pool = server.ModernBackendPool(_BACKEND, idle_ttl=30.0, now=lambda: clock[0])

    def _probing_now():
        # False from a non-blocking acquire means this thread is already
        # inside the lock — i.e. publication is atomic.
        got = pool._lock.acquire(blocking=False)
        if got:
            pool._lock.release()
        observations.append(not got)
        return clock[0]

    pool._now = _probing_now
    try:
        _, _, entry = pool.get_or_create("newborn")
        assert observations, "the publication path never stamped `used`"
        assert observations[-1] is True, (
            "the newborn was published outside the pool lock — a reaper "
            "could take it before its hold existed"
        )
        assert entry["holds"] == 1
        assert entry["used"] == clock[0]
        pool.release(entry)
    finally:
        pool.shutdown_all()


def test_restarting_the_reaper_does_not_leave_two_running():
    """#379 Copilot review — a restart must not un-stop its predecessor.

    `stop_reaper` does not join: the thread is a daemon parked in
    `wait(interval)`. With a SHARED stop event, a restart that cleared it
    could revive a predecessor that had not yet observed the set, leaving
    two reapers sweeping the same pool. Each loop now closes over the
    event it was born with, so a stop is permanent for that thread.

    Revert-check: sharing one event and clearing it on start leaves the
    first thread alive.
    """
    pool = server.ModernBackendPool(_BACKEND, idle_ttl=30.0)
    try:
        pool.start_reaper()
        first = pool._reaper
        assert first is not None and first.is_alive()
        first_stop = pool._reaper_stop

        pool.stop_reaper()
        pool.start_reaper()
        second = pool._reaper
        assert second is not None and second is not first

        # The first thread's own event stays set no matter what the
        # restart did to the pool's current one.
        assert first_stop.is_set()
        assert pool._reaper_stop is not first_stop
        assert not pool._reaper_stop.is_set()
    finally:
        pool.shutdown_all()
