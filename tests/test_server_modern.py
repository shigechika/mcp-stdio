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
import hmac
import hashlib
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
        # "MUST respond with 404 Not Found".
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
        and -32601.

        This used to be pinned with `subscriptions/listen`, which #374
        now intercepts before it can reach a child — so the rule is
        pinned on a method the fake child genuinely does not implement.
        The rule itself is unchanged and still general.
        """
        body = _modern_body("resources/list", meta=_meta())
        resp = _post(gateway, body, _modern_headers("resources/list"))
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

        The newcomer itself does not survive the checkout, though (#379
        review): `busy` stays not-reapable (a request is still on the
        wire), so once `other` is released it is the ONLY reapable
        entry, and `release()`'s own sweep reclaims it right away —
        trimming the pool back to the cap rather than leaving the
        overshoot to sit there.
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
            # `other`'s own release leaves it the only reapable entry
            # (busy is still mid-request), so release()'s sweep (#379
            # review) reclaims `other` immediately rather than letting
            # the overshoot persist.
            assert pool.count() == 1, (
                "release() should have reclaimed the transient newcomer"
            )
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

        The newcomer itself does not survive the checkout, though (#379
        review): `held` stays unevictable (still checked out), so once
        `other` is released it is the ONLY reapable entry, and
        `release()`'s own sweep reclaims it right away — trimming the
        pool back to the cap rather than leaving the overshoot to sit
        there.
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
            # `other`'s own release leaves it the only reapable entry
            # (`held`/"first" is still checked out), so release()'s
            # sweep (#379 review) reclaims `other` immediately.
            assert pool.count() == 1, (
                "release() should have reclaimed the transient newcomer"
            )
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
        """#376 §3.2 / #379 review — an overshoot that used to be permanent.

        Racing first-requests each insert a PENDING placeholder, and a
        placeholder is not evictable, so once the ready-quiet victims run
        out every racer logs "exceeding the cap" and inserts anyway. That
        is the overshoot this test provokes: both racers park with their
        placeholders in the map before either publishes.

        What resolves it, today, is `release()`'s own sweep (#379
        review), not the post-spawn re-check this test originally
        targeted: releasing alice makes her the ONLY reapable entry (bob
        is still PENDING, not evictable), so her own release-sweep evicts
        her immediately — the post-spawn sweep never gets a chance to act
        first. This test now pins the OUTCOME (the pool re-bounds to the
        cap once the race resolves), not a specific mechanism; the
        release-sweep's own mechanism-level revert-check lives in
        `test_release_re_sweeps_an_overshoot_left_by_a_spawn_race`.

        Both racers are still released ONE AT A TIME, and that ordering
        is still deliberate: it is what makes alice reapable-but-bob-not
        at her release, so the outcome is deterministic rather than a
        race the CI host wins or loses (it lost on Windows, where the
        slower spawn let both children be held at once — see
        `test_release_re_sweeps_...` for that simultaneous-hold shape).
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

            # Alice finishes and releases. Bob is still PENDING (no
            # backend yet), so he is not a candidate — alice is the ONLY
            # reapable entry, and her own release-sweep (#379 review)
            # reclaims her immediately.
            gates["alice"].set()
            assert done["alice"].wait(timeout=30)
            assert pool.count() == 1, (
                "alice's own release-sweep should have reclaimed her"
            )

            # Bob finishes and releases. The pool is already back at cap,
            # so this is a no-op sweep — the outcome (re-bounded to cap)
            # was already reached by alice's release.
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

    def test_release_re_sweeps_an_overshoot_left_by_a_spawn_race(self):
        """#379 review, /code-review score 100: with `max_children=1`, two
        principals racing their FIRST requests each insert a PENDING
        placeholder, each spawns, each publishes — and unlike the
        one-at-a-time release above, HERE both are released with the
        OTHER still held throughout its own publish, so neither
        publish-time sweep (#376 §3.2) can ever evict the other: the
        pool settles at 2, BOTH held simultaneously. This is the
        documented transient overshoot.

        Before this fix, `release()` only decremented `holds` — nothing
        re-swept afterward, so this overshoot was PERMANENT in a
        fixed-principal deployment: no new principal ever arrives to
        trigger the pre-insert sweep, and the idle reaper does not save
        it at the default `--modern-idle-ttl 0`.
        """
        pool = server.ModernBackendPool(_BACKEND, max_children=1)
        both_pending = threading.Barrier(3)
        gates = {"alice": threading.Event(), "bob": threading.Event()}
        published = {"alice": threading.Event(), "bob": threading.Event()}
        entries: dict[str, dict] = {}
        current = threading.local()
        real_spawn = pool._spawn_and_handshake

        def _gated_spawn():
            both_pending.wait(timeout=15)
            assert gates[current.principal].wait(timeout=15)
            return real_spawn()

        pool._spawn_and_handshake = _gated_spawn

        def _racer(principal):
            current.principal = principal
            _, _, entry = pool.get_or_create(principal)
            entries[principal] = entry
            published[principal].set()
            # Deliberately does NOT release — the main thread holds both
            # checkouts open until it has proven the overshoot, then
            # releases both itself (release() does not care which thread
            # calls it).

        threads = [
            threading.Thread(target=_racer, args=(name,), daemon=True)
            for name in ("alice", "bob")
        ]
        try:
            for t in threads:
                t.start()
            both_pending.wait(timeout=15)
            assert pool.count() == 2, "the racers did not both hold a placeholder"

            gates["alice"].set()
            gates["bob"].set()
            assert published["alice"].wait(timeout=30)
            assert published["bob"].wait(timeout=30)
            # Both children are READY and HELD at once — the state that
            # makes this a real overshoot, not merely two placeholders.
            assert pool.count() == 2, "both children should still be held"

            pool.release(entries["alice"])
            pool.release(entries["bob"])
            assert pool.count() == 1, "release() never re-swept the cap overshoot"
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

    def test_all_four_flags_are_advertised_when_the_child_supports_them(self):
        """The un-strip, completed by #381.

        The rule is the relay's C8 principle in reverse — advertise a
        notification flag only for a kind serve can actually deliver.
        Before #374 all four were stripped, because a pooled child's
        notifications went nowhere. #374's `subscriptions/listen` made the
        listChanged trio true; #381 made `resources.subscribe` true too,
        by actually driving the subscription against the child.

        A child advertising all four now has all four echoed — but only
        BECAUSE it advertises `subscribe` itself, which the next test
        pins from the other side.
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
        assert caps["tools"] == {"listChanged": True}
        assert caps["prompts"] == {"listChanged": True}
        assert caps["resources"] == {"subscribe": True, "listChanged": True}
        # Control: an unrelated capability passes through untouched,
        # proving the filter is scoped rather than over-stripping.
        assert caps["completions"] == {}

    def test_subscribe_is_stripped_when_the_child_does_not_support_it(self):
        """The conditional half — and why the table entry survives #381.

        Serve honors `resourceSubscriptions` only by driving
        `resources/subscribe` at the child, so a child that does not
        advertise it makes the flag a promise serve cannot keep.
        `subscribe: false` is the case that makes this observable at all:
        the key is PRESENT, so a raw echo would forward a falsy flag the
        ack would then also decline.
        """
        result = server._synthesize_discover_result(
            {"capabilities": {"resources": {"subscribe": False, "listChanged": True}}}
        )
        assert result["capabilities"]["resources"] == {"listChanged": True}

    def test_the_discover_gate_and_the_ack_gate_are_one_predicate(self):
        """Pinned against each other rather than restated.

        Two independent capability checks would be free to drift — serve
        advertising `subscribe` while the ack declines it, or the reverse
        — and both are invisible until a client actually tries.
        """
        for init_result, expected in (
            ({"capabilities": {"resources": {"subscribe": True}}}, True),
            ({"capabilities": {"resources": {"subscribe": False}}}, False),
            ({"capabilities": {"resources": {}}}, False),
            ({"capabilities": {}}, False),
        ):
            resources = server._synthesize_discover_result(init_result)[
                "capabilities"
            ].get("resources", {})
            assert ("subscribe" in resources) is expected
            assert server._child_supports_resource_subscribe(init_result) is expected

    def test_the_advertised_trio_matches_what_listen_forwards(self):
        """The advertisement and the delivery table cannot drift apart.

        `_UNDELIVERABLE_NOTIFICATION_FLAGS` and `_LISTEN_FILTER_METHODS`
        are two statements of the same fact in different vocabularies
        (capability flags vs wire method names). Pinning them against
        each other is what makes "advertise exactly what is forwarded"
        an enforced invariant rather than a comment.
        """
        assert server._UNDELIVERABLE_NOTIFICATION_FLAGS == {"resources": ("subscribe",)}
        assert set(server._LISTEN_FILTER_METHODS.values()) == {
            "notifications/tools/list_changed",
            "notifications/resources/list_changed",
            "notifications/prompts/list_changed",
        }

    def test_a_non_stripped_key_survives_within_a_stripped_family(self):
        """The filter removes specific KEYS, never the whole family
        object: a hypothetical `resources.other` flag must survive
        alongside `subscribe` being stripped from the SAME family — spec
        capability semantics are presence-based per key, not per family.

        `subscribe: False` is what makes this reachable post-#381: a
        truthy `subscribe` is now KEPT (serve can honor it), so the
        stripping path needs a child that does not support it.
        """
        result = server._synthesize_discover_result(
            {"capabilities": {"resources": {"subscribe": False, "other": "x"}}}
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
            {"capabilities": {"tools": True, "resources": {"subscribe": False}}}
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


# --- subscriptions/listen (#374) -----------------------------------------

LISTEN_METHOD = "subscriptions/listen"
ACK_METHOD = "notifications/subscriptions/acknowledged"
SUBSCRIPTION_ID = "io.modelcontextprotocol/subscriptionId"
INTERNAL_ERROR = -32603
INVALID_REQUEST = -32600
TRIO = ("tools", "prompts", "resources")


def _listen_body(
    req_id: object = "listen-1",
    *,
    notifications: object = "unset",
    notification: bool = False,
) -> dict:
    params: dict = {"_meta": _meta()}
    if notifications != "unset":
        params["notifications"] = notifications
    body: dict = {"jsonrpc": "2.0", "method": LISTEN_METHOD, "params": params}
    if not notification:
        body["id"] = req_id
    return body


def _fire(url: str, family: str = "tools") -> None:
    """Make the pooled child emit one listChanged notification.

    A modern NOTIFICATION, so it rides the same oneway arm to the same
    per-principal child the listen stream is attached to — which is the
    only way to drive a real fan-out from outside the gateway.
    """
    resp = _post(
        url,
        {
            "jsonrpc": "2.0",
            "method": "trigger_list_changed",
            "params": {"family": family, "_meta": _meta()},
        },
    )
    assert resp.status_code == 202, resp.text


class _Listener:
    """A `subscriptions/listen` stream read on a daemon thread.

    The read has to be off the test's thread: driving an event means
    POSTing to the same gateway while the stream is open, and the ack
    itself arrives before there is anything to POST.

    Frames and keepalive comments are kept separately — several pins
    turn on "a keepalive arrived and the event did NOT", which is the
    determinism bound for asserting a NEGATIVE about a stream.
    """

    def __init__(self, url: str, body: dict, *, accept: str = "text/event-stream"):
        self.url = url
        self.body = body
        self.accept = accept
        self.frames: list[dict] = []
        self.comments: list[str] = []
        self.status: int | None = None
        self.headers: dict[str, str] = {}
        self.error_body: bytes = b""
        self.ended = threading.Event()
        self.opened = threading.Event()
        self._lock = threading.Lock()
        self._response: httpx.Response | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> "_Listener":
        self._thread.start()
        assert self.opened.wait(timeout=15), "the listen stream never responded"
        return self

    def __exit__(self, *exc) -> None:
        self.disconnect()

    def _run(self) -> None:
        headers = {
            **_modern_headers(LISTEN_METHOD),
            "Accept": self.accept,
            "Content-Type": "application/json",
        }
        try:
            with httpx.stream(
                "POST",
                self.url,
                content=json.dumps(self.body),
                headers=headers,
                timeout=None,
            ) as resp:
                self._response = resp
                self.status = resp.status_code
                self.headers = dict(resp.headers)
                if resp.status_code != 200:
                    self.error_body = resp.read()
                    return
                self.opened.set()
                for line in resp.iter_lines():
                    if line.startswith("data: "):
                        with self._lock:
                            self.frames.append(json.loads(line[len("data: ") :]))
                    elif line.startswith(":"):
                        with self._lock:
                            self.comments.append(line[1:].strip())
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            self.error_body = repr(exc).encode()
        finally:
            self.opened.set()
            self.ended.set()

    def disconnect(self) -> None:
        """Close from the test's side — the client-goes-away path."""
        resp = self._response
        if resp is not None:
            try:
                resp.close()
            except Exception:  # noqa: BLE001 - teardown, best effort
                pass
        self._thread.join(timeout=10)

    def snapshot(self) -> tuple[list[dict], list[str]]:
        with self._lock:
            return list(self.frames), list(self.comments)

    def wait_frames(self, count: int, timeout: float = 15.0) -> list[dict]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            frames, _ = self.snapshot()
            if len(frames) >= count:
                return frames
            if self.ended.is_set():
                break
            time.sleep(0.01)
        frames, comments = self.snapshot()
        raise AssertionError(
            f"wanted {count} frames, saw {len(frames)}: {frames} (comments={comments})"
        )

    def wait_comments(self, count: int, timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _, comments = self.snapshot()
            if len(comments) >= count:
                return
            time.sleep(0.01)
        raise AssertionError(f"no keepalive within {timeout}s")


@pytest.fixture()
def quick_keepalive(monkeypatch):
    """Shrink the keepalive so a NEGATIVE assertion has a bound.

    "The event did not arrive" is only provable against something that
    DID: the next keepalive comment. At the production 15 s that is a
    15 s test, so the interval is shortened rather than the assertion
    weakened into a sleep.
    """
    monkeypatch.setattr(server, "_SSE_KEEPALIVE_SECS", 0.3)


class TestListenAck:
    """The ack is the protocol's first and most load-bearing frame."""

    def test_the_ack_is_frame_one_and_carries_the_honored_subset(self, gateway):
        """Spec: the server "MUST send
        `notifications/subscriptions/acknowledged` as the first message
        ... and MUST NOT send any notification on the subscription
        before it."

        The A9 nesting is asserted key by key because it is exactly the
        class of mistake a spec-shaped reading misses: `notifications`
        and the subscription id live INSIDE `params`, and a top-level
        echo is silently ignored by a compliant client — which then
        forwards nothing and reports no error.
        """
        with _Listener(
            gateway, _listen_body(notifications={"toolsListChanged": True})
        ) as ln:
            ack = ln.wait_frames(1)[0]
        assert ack["method"] == ACK_METHOD
        assert ack["jsonrpc"] == "2.0"
        # A notification, not a response: an `id` here would make a
        # client correlate it to the listen request and settle the route.
        assert "id" not in ack
        assert ack["params"]["notifications"] == {"toolsListChanged": True}
        assert ack["params"]["_meta"][SUBSCRIPTION_ID] == "listen-1"
        # A9, the other direction: nothing at the top level.
        assert "notifications" not in ack
        assert "_meta" not in ack

    def test_a_string_listen_id_is_echoed_verbatim(self, gateway):
        """The v2 client mints ids like `"listen-1"` and routes on the
        stamp, so any coercion (to int, to str, to a minted id) silently
        strands every frame."""
        with _Listener(
            gateway, _listen_body("sub/42", notifications={"toolsListChanged": True})
        ) as ln:
            ack = ln.wait_frames(1)[0]
        assert ack["params"]["_meta"][SUBSCRIPTION_ID] == "sub/42"

    def test_an_absent_filter_still_acks_with_an_empty_object(self, gateway):
        """ "Subscribed to nothing" is a valid subscription.

        The `notifications` KEY must be present even when empty: the v2
        client reads a missing one as malformed and discards the whole
        ack, which times out the caller rather than failing loudly.
        """
        with _Listener(gateway, _listen_body()) as ln:
            ack = ln.wait_frames(1)[0]
        assert ack["params"]["notifications"] == {}

    def test_unknown_filter_keys_are_not_echoed_as_honored(self, gateway):
        """Honor-all applies to the trio, not to anything sent.

        Echoing a key serve cannot deliver would promise forwarding that
        never happens — the same failure the discover un-strip exists to
        avoid, one layer down.
        """
        with _Listener(
            gateway,
            _listen_body(
                notifications={
                    "toolsListChanged": True,
                    "resourceUpdated": True,
                    "loggingMessage": True,
                }
            ),
        ) as ln:
            ack = ln.wait_frames(1)[0]
        assert ack["params"]["notifications"] == {"toolsListChanged": True}

    def test_a_false_flag_is_not_honored(self, gateway):
        """`False` means "do not send me these", not "the key exists"."""
        with _Listener(
            gateway,
            _listen_body(
                notifications={"toolsListChanged": False, "promptsListChanged": True}
            ),
        ) as ln:
            ack = ln.wait_frames(1)[0]
        assert ack["params"]["notifications"] == {"promptsListChanged": True}

    def test_the_stream_mints_no_session(self, gateway):
        """A modern exchange leaves no session behind — a long-lived one
        is the most tempting place to reintroduce one."""
        with _Listener(gateway, _listen_body()) as ln:
            ln.wait_frames(1)
            headers = ln.headers
        assert "mcp-session-id" not in headers, headers
        assert headers.get("content-type") == "text/event-stream"


class TestListenDelivery:
    """Fan-out from the pooled child to the streams that asked."""

    def test_a_matching_event_reaches_the_stream_stamped(self, gateway):
        with _Listener(
            gateway, _listen_body(notifications={"toolsListChanged": True})
        ) as ln:
            ln.wait_frames(1)
            _fire(gateway, "tools")
            event = ln.wait_frames(2)[1]
        assert event["method"] == "notifications/tools/list_changed"
        assert event["params"]["from"] == "tools"
        # Every frame is stamped, not just the ack: the client routes on
        # this, so an unstamped frame never reaches the consumer.
        assert event["params"]["_meta"][SUBSCRIPTION_ID] == "listen-1"
        assert "id" not in event

    def test_an_event_in_the_attach_to_ack_window_is_buffered_not_lost(
        self, monkeypatch
    ):
        """Why the stream attaches BEFORE the ack is written.

        There is a window between "this stream is committed" and "the
        client has been acknowledged". A child that fires during it has
        nowhere to be delivered unless the buffer already exists — and
        the loss is SILENT: the client sees a healthy stream that simply
        never mentioned the change it was subscribed to.

        The publish is driven from inside the ack write, so the window is
        entered deterministically rather than raced into with a sleep.

        Revert-check: move `backend.attach_listener(listener)` below
        `self._write_sse(...)` in `_serve_listen_stream` and the child's
        notification lands with zero listeners attached, is discarded,
        and only the ack ever arrives.
        """
        httpd, registry = server.build_server(_BACKEND, host="127.0.0.1", port=0)
        host, port = httpd.server_address[0], httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        url = f"http://{host}:{port}/mcp"

        original = server._Handler._write_sse

        def _publish_before_the_ack(handler, message):
            if message.get("method") == ACK_METHOD:
                for entry in list(httpd.modern_pool._entries.values()):
                    backend = entry.get("backend")
                    if backend is not None:
                        backend._queue_server_initiated(
                            json.dumps(
                                {
                                    "jsonrpc": "2.0",
                                    "method": "notifications/tools/list_changed",
                                    "params": {"window": "pre-ack"},
                                }
                            )
                        )
            return original(handler, message)

        monkeypatch.setattr(server._Handler, "_write_sse", _publish_before_the_ack)
        try:
            with _Listener(
                url, _listen_body(notifications={"toolsListChanged": True})
            ) as ln:
                frames = ln.wait_frames(2)
        finally:
            httpd.shutdown()
            registry.shutdown_all()
            httpd.modern_pool.shutdown_all()
            httpd.server_close()

        # The ack is still first — buffering must not reorder it.
        assert frames[0]["method"] == ACK_METHOD
        assert frames[1]["params"]["window"] == "pre-ack"
        assert frames[1]["params"]["_meta"][SUBSCRIPTION_ID] == "listen-1"

    def test_each_family_of_the_trio_is_deliverable(self, gateway):
        """The advertisement the discover un-strip makes, proven one
        family at a time rather than inferred from the tools case."""
        with _Listener(
            gateway,
            _listen_body(
                notifications={
                    "toolsListChanged": True,
                    "promptsListChanged": True,
                    "resourcesListChanged": True,
                }
            ),
        ) as ln:
            ln.wait_frames(1)
            for family in TRIO:
                _fire(gateway, family)
            frames = ln.wait_frames(4)
        assert [f["method"] for f in frames[1:]] == [
            f"notifications/{family}/list_changed" for family in TRIO
        ]

    def test_an_unrequested_family_is_suppressed(self, gateway, quick_keepalive):
        """Spec: "The server MUST NOT send notification types the client
        has not explicitly requested."

        Bounded by the keepalive rather than by a sleep: the comment
        proves the pump ran and chose to send nothing.
        """
        with _Listener(
            gateway, _listen_body(notifications={"toolsListChanged": True})
        ) as ln:
            ln.wait_frames(1)
            _fire(gateway, "prompts")
            ln.wait_comments(2)
            frames, _ = ln.snapshot()
        assert len(frames) == 1, frames

    def test_a_non_trio_notification_is_never_forwarded(self, gateway, quick_keepalive):
        """`notifications/message` is request-scoped — it belongs to
        whatever carried the request, not to a broadcast stream (#381).
        Requesting the whole trio must not turn the stream into a
        firehose for everything the child says."""
        with _Listener(
            gateway,
            _listen_body(
                notifications={
                    "toolsListChanged": True,
                    "promptsListChanged": True,
                    "resourcesListChanged": True,
                }
            ),
        ) as ln:
            ln.wait_frames(1)
            assert (
                _post(
                    gateway,
                    {
                        "jsonrpc": "2.0",
                        "method": "trigger_push",
                        "params": {"_meta": _meta()},
                    },
                ).status_code
                == 202
            )
            ln.wait_comments(2)
            frames, _ = ln.snapshot()
        assert len(frames) == 1, frames

    def test_a_malformed_notification_is_stamped_not_fatal(self, monkeypatch):
        """#382 Copilot review — a misbehaving child must not be able to
        drop a well-behaved client's subscription.

        A notification whose `params` is not an object (`"params":
        "oops"`) used to reach `dict(...)` on the handler thread and
        raise `ValueError` there, killing the stream abruptly — the
        client would see it as LOST and re-listen, into the same child.
        It now degrades: the malformed part is forfeited, the connection
        is not, and the stamp the client routes on still arrives.

        Same posture `_strip_undeliverable_capability_flags` takes for
        the same reason (#373 review R3F1).

        Revert-check: restore `dict(stamped.get("params") or {})` and the
        stream ends with only the ack on it.
        """
        httpd, registry = server.build_server(_BACKEND, host="127.0.0.1", port=0)
        host, port = httpd.server_address[0], httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        url = f"http://{host}:{port}/mcp"
        try:
            with _Listener(
                url, _listen_body(notifications={"toolsListChanged": True})
            ) as ln:
                ln.wait_frames(1)
                for entry in list(httpd.modern_pool._entries.values()):
                    backend = entry.get("backend")
                    if backend is not None:
                        backend._queue_server_initiated(
                            json.dumps(
                                {
                                    "jsonrpc": "2.0",
                                    "method": "notifications/tools/list_changed",
                                    "params": "oops",
                                }
                            )
                        )
                event = ln.wait_frames(2)[1]
        finally:
            httpd.shutdown()
            registry.shutdown_all()
            httpd.modern_pool.shutdown_all()
            httpd.server_close()
        assert event["method"] == "notifications/tools/list_changed"
        assert event["params"]["_meta"][SUBSCRIPTION_ID] == "listen-1"

    def test_two_streams_on_one_child_each_get_their_own_stamp(self, gateway):
        """Both streams share the pooled child (same principal), so this
        pins fan-out proper: one parse, two deliveries, two ids."""
        first = _Listener(
            gateway, _listen_body("a", notifications={"toolsListChanged": True})
        )
        second = _Listener(
            gateway, _listen_body("b", notifications={"toolsListChanged": True})
        )
        with first, second:
            first.wait_frames(1)
            second.wait_frames(1)
            _fire(gateway, "tools")
            a_event = first.wait_frames(2)[1]
            b_event = second.wait_frames(2)[1]
        assert a_event["params"]["_meta"][SUBSCRIPTION_ID] == "a"
        assert b_event["params"]["_meta"][SUBSCRIPTION_ID] == "b"
        assert a_event["method"] == b_event["method"]

    def test_fan_out_hands_both_streams_the_same_parsed_object(self):
        """Why the two-stamp test above is not redundant.

        `_queue_server_initiated` parses ONCE and publishes the same dict
        to every matching stream — so a pump that stamped IN PLACE would
        ship the first stream's subscription id on the second stream's
        frame. This pins the sharing that makes that hazard real; the
        end-to-end test above pins that the pump copies instead.
        """
        message = {
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": {"_meta": {"childKey": 1}},
        }
        a = server._ListenStream("a", {"toolsListChanged": True})
        b = server._ListenStream("b", {"toolsListChanged": True})
        a.publish(message)
        b.publish(message)
        assert a.next_message(1.0) is b.next_message(1.0) is message


@pytest.mark.parametrize(
    ("accept_header", "expected"),
    [
        ("text/event-stream", True),
        ("Text/Event-Stream", True),
        ("text/*", True),
        ("*/*", True),
        ("application/json, text/event-stream", True),
        ("text/event-stream;q=0", False),
        ("text/event-stream;q=0.5", True),
        ("application/json", False),
        (None, True),
        ("", True),
        ("text/event-stream ; q=0", False),
        # #382 review R6F1: a positive wildcard must not override a more
        # specific explicit refusal — RFC 9110 §12.5.1 says the MOST
        # SPECIFIC matching range decides.
        ("text/event-stream;q=0, */*", False),
        ("text/event-stream;q=0, */*;q=1", False),
        ("text/*;q=0, */*", False),  # subtype wildcard beats full wildcard
        ("text/event-stream, text/*;q=0", True),  # exact beats subtype wildcard
        ("text/event-stream;q=0, text/event-stream", True),  # same-tier: max
    ],
)
def test_accepts_sse_matches_media_ranges(accept_header, expected):
    """#382 review R1F2 remainder — table-driven over the helper directly.

    A prior fix casefolded the old substring check but left two classes
    of media-range handling wrong in opposite directions: `text/*` is a
    valid range that MATCHES `text/event-stream` but does not contain
    that literal substring, so it earned a false 406; `;q=0` is an
    explicit REFUSAL (RFC 9110 §12.4.2) that the substring check does
    not parse at all, so it was let through. Absent/empty is RFC
    9110 §12.5.1's "accept anything", which the substring check also
    got backwards (`""` contains no substring, so omitting Accept
    entirely earned a 406).

    The R6F1 rows are precedence, not matching: `_accepts_sse` used to
    accept if ANY matching range had `q>0`, so a trailing `*/*` could
    override an explicit `text/event-stream;q=0` refusal earlier in the
    same header. RFC 9110 §12.5.1 says the MOST SPECIFIC matching range
    decides — exact beats `text/*` beats `*/*` — and the last row is the
    documented same-tier tie-break (the range listed twice with
    different `q` takes the max, leniently).
    """
    assert server._accepts_sse(accept_header) is expected


class TestListenRejections:
    """Everything refused BEFORE a stream is committed."""

    def test_a_non_object_filter_is_invalid_params(self, gateway):
        resp = _post(
            gateway,
            _listen_body(notifications=["toolsListChanged"]),
            {**_modern_headers(LISTEN_METHOD), "Accept": "text/event-stream"},
        )
        assert resp.status_code == 400, resp.text
        assert resp.json()["error"]["code"] == INVALID_PARAMS
        assert resp.json()["id"] == "listen-1"
        assert "mcp-session-id" not in resp.headers

    def test_an_id_less_listen_is_rejected_not_forwarded(self, gateway):
        """A notification-shaped listen has no id for the ack to stamp,
        so every frame it produced would be unroutable. Rejected at the
        notification arm rather than forwarded oneway with a 202."""
        resp = _post(
            gateway,
            _listen_body(notification=True, notifications={"toolsListChanged": True}),
            {**_modern_headers(LISTEN_METHOD), "Accept": "text/event-stream"},
        )
        assert resp.status_code == 400, resp.text
        assert resp.json()["error"]["code"] == INVALID_REQUEST

    def test_a_client_that_cannot_accept_sse_gets_406(self, gateway):
        resp = _post(
            gateway,
            _listen_body(),
            {**_modern_headers(LISTEN_METHOD), "Accept": "application/json"},
        )
        assert resp.status_code == 406, resp.text
        assert resp.json()["error"]["code"] == INVALID_REQUEST

    def test_a_wildcard_accept_is_enough(self, gateway):
        with _Listener(gateway, _listen_body(), accept="*/*") as ln:
            assert ln.wait_frames(1)[0]["method"] == ACK_METHOD

    def test_the_accept_check_is_case_insensitive(self, gateway):
        """#382 Copilot review. "Media types are case-insensitive"
        (RFC 9110 §8.3.1), so this is the SAME request as the lowercase
        one and a 406 here would be rejecting a client over its
        capitalisation.

        NO `*/*` in the header, deliberately: with a wildcard present the
        other branch of the check accepts it and the test proves nothing
        about case at all. (It was written that way first, and the
        revert-check is what caught it.)

        Revert-check: drop the `.lower()` and this earns a 406.
        """
        with _Listener(gateway, _listen_body(), accept="Text/Event-Stream") as ln:
            assert ln.status == 200, ln.error_body
            assert ln.wait_frames(1)[0]["method"] == ACK_METHOD

    def test_a_text_star_range_is_enough(self, gateway):
        """#382 review R1F2 remainder. `text/*` is a valid media RANGE
        that matches `text/event-stream` (RFC 9110 §12.5.1), but the old
        substring check missed it — `"text/*"` does not contain the
        literal substring `"text/event-stream"`.

        Revert-check: swap `_accepts_sse` back for the substring check
        and this earns a 406.
        """
        with _Listener(gateway, _listen_body(), accept="text/*") as ln:
            assert ln.status == 200, ln.error_body
            assert ln.wait_frames(1)[0]["method"] == ACK_METHOD

    def test_an_explicit_q_zero_refusal_earns_406(self, gateway):
        """#382 review R1F2 remainder. `q=0` is an explicit REFUSAL of a
        media range (RFC 9110 §12.4.2 — "a value of 0 means 'not
        acceptable'"), but the old substring check does not parse
        quality parameters at all, so `text/event-stream;q=0` passed it
        and opened a stream the client had explicitly said it did not
        want.

        Revert-check: swap `_accepts_sse` back for the substring check
        and this gets a 200 stream instead of a 406.
        """
        resp = _post(
            gateway,
            _listen_body(),
            {**_modern_headers(LISTEN_METHOD), "Accept": "text/event-stream;q=0"},
        )
        assert resp.status_code == 406, resp.text
        assert resp.json()["error"]["code"] == INVALID_REQUEST

    def test_a_positive_wildcard_does_not_override_an_explicit_refusal(self, gateway):
        """#382 review R6F1. A trailing `*/*;q=1` used to overrule an
        earlier, more specific `text/event-stream;q=0` refusal — the old
        logic accepted if ANY matching range had `q>0`. RFC 9110 §12.5.1
        says the MOST SPECIFIC matching range decides, so the explicit
        refusal wins regardless of what a wildcard later in the same
        header says.

        Revert-check: restore the any-match logic and this gets a 200
        stream instead of a 406.
        """
        resp = _post(
            gateway,
            _listen_body(),
            {
                **_modern_headers(LISTEN_METHOD),
                "Accept": "text/event-stream;q=0, */*;q=1",
            },
        )
        assert resp.status_code == 406, resp.text
        assert resp.json()["error"]["code"] == INVALID_REQUEST

    def test_the_per_child_stream_cap_is_refused_pre_ack(self, gateway, monkeypatch):
        """One client must not be able to pin unbounded handler threads.

        `-32603` rather than a fresh `-32000`-range mint (O18), and
        BEFORE the ack — a client that got an ack and then a close would
        have to guess whether it had missed events.
        """
        monkeypatch.setattr(server, "_LISTEN_MAX_STREAMS_PER_CHILD", 1)
        with _Listener(gateway, _listen_body("first")) as ln:
            ln.wait_frames(1)
            resp = _post(
                gateway,
                _listen_body("second"),
                {**_modern_headers(LISTEN_METHOD), "Accept": "text/event-stream"},
            )
        assert resp.status_code == 503, resp.text
        assert resp.json()["error"]["code"] == INTERNAL_ERROR
        assert resp.json()["id"] == "second"

    def test_attach_listener_is_atomic_under_a_synchronized_burst(self):
        """#382 review R1F1 — the cap must survive a synchronized burst.

        Before this fix the caller checked `len(backend._snapshot_listeners())
        >= cap` and called `attach_listener` as two SEPARATE steps. Under
        a burst of simultaneous listens, every racer reads the count
        before ANY of them has attached, so every one of them sees a
        free slot and all attach — the cap bypassed by an arbitrary
        amount, and each attached stream pins a handler thread, which is
        exactly the DoS the cap exists to stop.

        `attach_listener` now does the check-and-attach as ONE atomic
        step under its own lock, so no matter how many callers race it
        concurrently, at most `cap` of them can ever succeed.

        A bare barrier before the call does NOT reproduce the old bug:
        measured directly, the reverted shape's check-to-attach window
        is a few bytecodes wide and never overshot in 20 trials at 200
        threads, nor in 10 trials at 300 threads with
        `sys.setswitchinterval(0.00001)` — CPython's GIL just does not
        preempt a window that small on its own. So the window is
        widened DELIBERATELY, the same seam idiom the spawn-race pool
        tests use (`_spawn_and_handshake` there, `_snapshot_listeners`
        here): every racer is parked, with its count already read,
        until all of them have read it — recreating "every racer sees a
        free slot" on demand instead of hoping the scheduler does.

        This seam belongs to the shape being reverted TO: the current,
        atomic `attach_listener` does not call `_snapshot_listeners` at
        all, so against the fix this patch is inert and the test is
        exercising the real lock, not the widening.

        Revert-check: restore the non-atomic check-then-attach shape and
        more than `cap` attach.
        """
        backend = server.BackendProcess(_BACKEND)
        try:
            cap = 4
            extra = 6
            total = cap + extra
            real_snapshot = backend._snapshot_listeners
            all_counted = threading.Barrier(total)

            def _widened_snapshot():
                # Only the reverted (non-atomic) `attach_listener` calls
                # this. Read the real count, then park every racer here
                # until all `total` of them have — the check-to-attach
                # window held open on purpose.
                result = real_snapshot()
                all_counted.wait(timeout=15)
                return result

            backend._snapshot_listeners = _widened_snapshot

            results: list[bool | None] = [None] * total

            def _attach(i):
                listener = server._ListenStream(f"burst-{i}", {})
                results[i] = backend.attach_listener(listener, cap)

            threads = [
                threading.Thread(target=_attach, args=(i,), daemon=True)
                for i in range(total)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            assert all(r is not None for r in results), "a racer never finished"
            assert results.count(True) == cap, results
            assert results.count(False) == extra, results
            assert len(backend._listeners) == cap
        finally:
            backend._snapshot_listeners = real_snapshot
            backend.shutdown()

    def test_the_ladder_still_runs_before_the_stream(self, gateway):
        """Listen is intercepted inside `_dispatch_modern`, which is
        downstream of the O6-O10 ladder — so a malformed modern listen
        earns its ladder code, not a stream."""
        body = _listen_body()
        resp = _post(
            gateway,
            body,
            {
                **_modern_headers(LISTEN_METHOD, version="2025-06-18"),
                "Accept": "text/event-stream",
            },
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == HEADER_MISMATCH


class TestListenEndings:
    """How a stream ends tells the peer what to do next (§3.6)."""

    def test_gateway_shutdown_ends_with_a_terminal_result(self):
        """The spec's own graceful example: an empty `resultType:
        "complete"` result, stamped, then close. It tells a compliant
        peer the subscription is over rather than lost — the v2 client
        settles a route with no terminal frame as an ERROR.
        """
        httpd, registry = server.build_server(_BACKEND, host="127.0.0.1", port=0)
        host, port = httpd.server_address[0], httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        url = f"http://{host}:{port}/mcp"
        try:
            ln = _Listener(url, _listen_body(notifications={"toolsListChanged": True}))
            with ln:
                ln.wait_frames(1)
                # The MODERN pool, not the session registry: a listen
                # stream is attached to a gateway-owned pooled child,
                # which the registry knows nothing about.
                httpd.modern_pool.shutdown_all()
                frames = ln.wait_frames(2)
                assert ln.ended.wait(timeout=15)
        finally:
            httpd.shutdown()
            registry.shutdown_all()
            httpd.server_close()
        terminal = frames[1]
        assert terminal["id"] == "listen-1"
        assert terminal["result"]["resultType"] == "complete"
        assert terminal["result"]["_meta"][SUBSCRIPTION_ID] == "listen-1"
        # NEVER a server-sent notifications/cancelled: the v2 client
        # settles a route naming it as LOST, which would turn every
        # graceful teardown into a failure at a compliant peer.
        assert all(f.get("method") != "notifications/cancelled" for f in frames)

    def test_a_shutdown_stays_graceful_even_when_the_drain_times_out(self, monkeypatch):
        """Why the ENDING is classified by its caller, not inferred.

        The drain is bounded. A slow client can outlast it, and then the
        children are torn down while the pump is still working — so a
        pump that read `backend.closed` would see a dead child and
        silently downgrade an orderly shutdown to LOST, telling a
        compliant peer to reconnect to a gateway that is going away.

        A zero-length drain forces exactly that ordering. The terminal
        frame must still be written, because `close_listeners` already
        said what kind of ending this is.

        Revert-check: replace `if listener.graceful:` in
        `_pump_listen_stream` with `if not listener.overflowed and not
        backend.closed:` and the terminal frame disappears here — while
        the ordinary shutdown test above still passes, which is why this
        one exists.
        """
        monkeypatch.setattr(server, "_LISTEN_DRAIN_SECS", 0.0)
        httpd, registry = server.build_server(_BACKEND, host="127.0.0.1", port=0)
        host, port = httpd.server_address[0], httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        url = f"http://{host}:{port}/mcp"
        try:
            ln = _Listener(url, _listen_body(notifications={"toolsListChanged": True}))
            with ln:
                ln.wait_frames(1)
                httpd.modern_pool.shutdown_all()
                frames = ln.wait_frames(2)
        finally:
            httpd.shutdown()
            registry.shutdown_all()
            httpd.server_close()
        assert frames[1]["result"]["resultType"] == "complete"
        assert frames[1]["id"] == "listen-1"

    def test_a_dead_child_ends_the_stream_with_no_terminal_frame(self, gateway):
        """Abrupt, deliberately. Serve is still alive and the contract is
        that the peer re-listens and refetches — a terminal `complete`
        would tell it the opposite, that the subscription finished
        normally and there is nothing to recover."""
        with _Listener(
            gateway, _listen_body(notifications={"toolsListChanged": True})
        ) as ln:
            ln.wait_frames(1)
            # `exit` makes the child leave; the reader thread notices EOF
            # and fails the backend, which wakes the stream.
            _post(
                gateway,
                {"jsonrpc": "2.0", "method": "exit", "params": {"_meta": _meta()}},
            )
            assert ln.ended.wait(timeout=20), "the stream never noticed the dead child"
            frames, _ = ln.snapshot()
        assert len(frames) == 1, frames
        assert frames[0]["method"] == ACK_METHOD

    def test_a_client_disconnect_frees_the_slot_promptly(self, gateway, monkeypatch):
        """On HTTP "closing the SSE response stream is itself the
        cancellation signal" — so a disconnect must free what the stream
        held, and PROMPTLY.

        Asserted through the CAP, because that is the observable a real
        client hits. An earlier version of this test opened a fresh
        stream and checked it worked, which a LEAKED listener passes
        untouched — the assertion and its docstring had drifted apart.

        The number that made this necessary is 30 seconds. Waiting for a
        write to fail is not enough: the first keepalive after a
        disconnect lands in the kernel's send buffer and succeeds, so
        only the SECOND one raises — two full keepalive intervals of a
        zombie stream holding a cap slot and a pool hold. A client on a
        flaky network that dropped and re-listened locked ITSELF out with
        503s. `_peer_gone` is what closes that window.

        Revert-check: delete the `_peer_gone` branch from
        `_pump_listen_stream` and this fails on 503 — the exact symptom,
        not a proxy for it.
        """
        monkeypatch.setattr(server, "_LISTEN_MAX_STREAMS_PER_CHILD", 1)
        ln = _Listener(gateway, _listen_body(notifications={"toolsListChanged": True}))
        with ln:
            ln.wait_frames(1)
        # Bounded poll rather than one shot: the detach happens on the
        # handler thread, so the test OBSERVES it rather than assuming it
        # already happened. Ten seconds is well inside one keepalive
        # interval, so a pass here cannot come from the old behaviour.
        deadline = time.monotonic() + 10
        last: int | None = None
        while time.monotonic() < deadline:
            fresh = _Listener(
                gateway, _listen_body("after", notifications={"toolsListChanged": True})
            )
            with fresh:
                last = fresh.status
                if last == 200:
                    assert fresh.wait_frames(1)[0]["method"] == ACK_METHOD
                    return
            time.sleep(0.05)
        raise AssertionError(
            f"the slot was still held 10s after the disconnect (status={last})"
        )


class TestListenStreamUnit:
    """The buffer itself, away from HTTP."""

    def test_a_full_backlog_ends_the_stream_rather_than_dropping_a_frame(
        self, monkeypatch
    ):
        """A gap is undetectable to the client; a lost stream is
        re-established with fresh state. And `publish` must NEVER block:
        it runs on the child's reader thread, which serves every other
        consumer of that child."""
        monkeypatch.setattr(server, "_LISTEN_QUEUE_MAX", 2)
        stream = server._ListenStream("x", {"toolsListChanged": True})
        for i in range(5):
            stream.publish({"jsonrpc": "2.0", "method": "n", "params": {"i": i}})
        assert stream.overflowed is True
        assert stream.ending is True
        # LOST, not graceful: the client has a hole in its event history
        # and a terminal `complete` would say it does not.
        assert stream.graceful is False

    def test_wants_matches_only_the_honored_flags(self):
        stream = server._ListenStream("x", {"toolsListChanged": True})
        assert stream.wants("notifications/tools/list_changed") is True
        assert stream.wants("notifications/prompts/list_changed") is False
        assert stream.wants("notifications/message") is False

    def test_signal_end_wakes_a_waiting_stream_promptly(self):
        """A blocked `queue.get` cannot be woken by an Event, so the wait
        is sliced. Without that, a shutdown or a dead child would take a
        full keepalive interval to be noticed.

        Revert-check: a single `self._queue.get(timeout=timeout)` makes
        this take the full timeout.
        """
        stream = server._ListenStream("x", {})
        started = threading.Event()
        elapsed: list[float] = []

        def _wait():
            started.set()
            begin = time.monotonic()
            assert stream.next_message(30.0) is None
            elapsed.append(time.monotonic() - begin)

        worker = threading.Thread(target=_wait, daemon=True)
        worker.start()
        assert started.wait(timeout=5)
        time.sleep(0.05)
        stream.signal_end(graceful=True)
        worker.join(timeout=10)
        assert elapsed and elapsed[0] < 5.0, elapsed

    def test_the_first_ending_wins(self):
        """A shutdown followed by the child's death is ONE ending with two
        symptoms. Letting the later symptom rewrite the classification
        would downgrade a graceful teardown the client may already have
        been told about — and would reintroduce, one layer down, exactly
        the race that moved this decision out of the pump."""
        stream = server._ListenStream("x", {})
        stream.signal_end(graceful=True)
        stream.signal_end(graceful=False)
        assert stream.graceful is True

        other = server._ListenStream("y", {})
        other.signal_end(graceful=False)
        other.signal_end(graceful=True)
        assert other.graceful is False


class TestListenAndThePool:
    """#374's use of #376's hold seam."""

    def test_a_live_listen_stream_pins_its_child_against_the_reaper(self, gateway):
        """A held entry is never reaped — `holds` is exactly the seam
        #376 built for this, and #374 is its first real user. A stream
        whose child was reaped under it would simply go silent, with no
        ending of any kind for the client to react to.

        Driven through a REAL stream over HTTP rather than a bare
        `get_or_create`: the latter re-tests #376's refcount and says
        nothing about whether the LISTEN path actually takes the hold and
        keeps it for the life of the stream. The pool's clock is
        injectable, so nothing here waits on wall time.
        """
        httpd, registry = server.build_server(_BACKEND, host="127.0.0.1", port=0)
        host, port = httpd.server_address[0], httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        url = f"http://{host}:{port}/mcp"
        clock = [1000.0]
        pool = httpd.modern_pool
        pool._now = lambda: clock[0]
        pool._idle_ttl = 30.0
        try:
            ln = _Listener(url, _listen_body(notifications={"toolsListChanged": True}))
            with ln:
                ln.wait_frames(1)
                clock[0] += 31.0
                assert pool.reap_idle() == 0, (
                    "reaped a child out from under a live listen stream"
                )
                assert pool.count() == 1
            # Stream closed: the hold is released on the handler thread,
            # so observe the reap becoming possible rather than assume it.
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                clock[0] += 31.0
                if pool.reap_idle() == 1:
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("the hold outlived the stream")
            assert pool.count() == 0
        finally:
            httpd.shutdown()
            registry.shutdown_all()
            pool.shutdown_all()
            httpd.server_close()

    def test_the_hold_is_released_when_the_stream_ends(self):
        """The other half: a hold kept forever makes the child
        permanently unreapable, which is a leak rather than a safety
        margin. Fake clock — the reaper's only time input is `now`."""
        clock = [1000.0]
        pool = server.ModernBackendPool(_BACKEND, idle_ttl=30.0, now=lambda: clock[0])
        try:
            backend, _, entry = pool.get_or_create("held")
            stream = server._ListenStream("s", {"toolsListChanged": True})
            assert backend.attach_listener(stream, server._LISTEN_MAX_STREAMS_PER_CHILD)
            assert entry["holds"] == 1
            clock[0] += 31.0
            assert pool.reap_idle() == 0, "reaped a child with a live listen stream"
            assert pool.count() == 1
            # What `_serve_listen_stream`'s `finally` does when the
            # stream ends: detach, then release the hold.
            backend.detach_listener(stream)
            pool.release(entry)
            clock[0] += 31.0
            assert pool.reap_idle() == 1
        finally:
            pool.shutdown_all()

    def test_shutdown_signals_every_attached_stream(self):
        """`shutdown_all` wakes listeners BEFORE tearing children down,
        so a graceful ending is still classifiable as graceful."""
        pool = server.ModernBackendPool(_BACKEND)
        try:
            backend, _, entry = pool.get_or_create("p")
            stream = server._ListenStream("s", {"toolsListChanged": True})
            assert backend.attach_listener(stream, server._LISTEN_MAX_STREAMS_PER_CHILD)
            pool.release(entry)
            pool.shutdown_all()
            assert stream.ending is True
        finally:
            pool.shutdown_all()


def test_a_pooled_child_discards_deliver_and_discard_again(gateway, quick_keepalive):
    """The flip, in both directions (#373 R1F2 <-> #374).

    Before a stream attaches, a pooled child's notifications are shed
    (there is no consumer, so anything queued is retained for the life of
    the process). While one is attached they are DELIVERED. After it
    detaches the shedding must resume — this is the assertion that
    notices if the fan-out ever leaves the queue re-armed.
    """
    _fire(gateway, "tools")  # discarded: nothing attached
    with _Listener(
        gateway, _listen_body(notifications={"toolsListChanged": True})
    ) as ln:
        ln.wait_frames(1)
        _fire(gateway, "tools")  # delivered
        assert ln.wait_frames(2)[1]["method"] == "notifications/tools/list_changed"
    _fire(gateway, "tools")  # discarded again
    # The gateway is still serving, which is the observable half: a
    # retained queue would be invisible here, so the pin is that the
    # NEXT stream still starts clean rather than replaying the shed one.
    with _Listener(
        gateway, _listen_body("next", notifications={"toolsListChanged": True})
    ) as ln:
        frames = ln.wait_frames(1)
        ln.wait_comments(2)
        frames, _ = ln.snapshot()
    assert len(frames) == 1, frames


# --- resourceSubscriptions (#381) ----------------------------------------

RESOURCE_FIELD = "resourceSubscriptions"
RESOURCE_UPDATED = "notifications/resources/updated"
_BACKEND_NO_SUBSCRIBE = [*_BACKEND, "--no-resource-subscribe"]


def _fire_resource_update(url: str, uri: str) -> None:
    """Make the pooled child emit one `notifications/resources/updated`."""
    resp = _post(
        url,
        {
            "jsonrpc": "2.0",
            "method": "trigger_resource_update",
            "params": {"uri": uri, "_meta": _meta()},
        },
    )
    assert resp.status_code == 202, resp.text


def _subscribe_calls(url: str) -> list[list]:
    """The child's own record of every subscribe/unsubscribe it received.

    WIRE EVIDENCE. Every refcount assertion in this file reads this rather
    than inferring from whether updates arrived: "no update showed up" is
    equally true when the subscription worked and nothing changed, when
    routing is broken, and when the whole feature is missing. A call log
    distinguishes them.
    """
    resp = _post(
        url,
        _modern_body("subscribe_log", meta=_meta()),
        _modern_headers("subscribe_log"),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["result"]["calls"]


@pytest.fixture()
def gateway_no_subscribe():
    """A gateway whose child does NOT advertise `resources.subscribe`."""
    httpd, registry = server.build_server(
        _BACKEND_NO_SUBSCRIBE, host="127.0.0.1", port=0
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


class TestResourceSubscriptionAck:
    """What the ack promises, and what gates it."""

    def test_requested_uris_are_echoed_when_the_child_supports_subscribe(self, gateway):
        """Honor-all above the capability gate: no per-URI accept/reject.

        There is no servability probe to base one on and the reference
        implementation has none — its own words are that "a subscription
        to a nonexistent resource URI is honored and never fires".
        """
        uris = ["res://a", "res://b"]
        with _Listener(
            gateway, _listen_body(notifications={RESOURCE_FIELD: uris})
        ) as ln:
            ack = ln.wait_frames(1)[0]
        assert ack["params"]["notifications"][RESOURCE_FIELD] == uris

    def test_a_child_without_the_capability_gets_the_field_omitted(
        self, gateway_no_subscribe
    ):
        """Omitted, NEVER `[]`.

        An empty list would claim the feature works and then deliver
        nothing; omission is the spec's own "notification types the
        server does not support are omitted", and it is what a client
        checking the ack (the spec's SHOULD) can act on.
        """
        with _Listener(
            gateway_no_subscribe,
            _listen_body(notifications={RESOURCE_FIELD: ["res://a"]}),
        ) as ln:
            ack = ln.wait_frames(1)[0]
        notifications = ack["params"]["notifications"]
        assert RESOURCE_FIELD not in notifications, notifications
        # The object itself is still present — a MISSING `notifications`
        # key makes the v2 client discard the whole ack and time out.
        assert notifications == {}

    def test_nothing_is_driven_against_a_child_without_the_capability(
        self, gateway_no_subscribe
    ):
        """The gate is not cosmetic: it must also stop the drive.

        Asserted on the child's own call log — a capability-lacking child
        has no documented error for an unsolicited `resources/subscribe`,
        so serve simply must never send one.
        """
        with _Listener(
            gateway_no_subscribe,
            _listen_body(notifications={RESOURCE_FIELD: ["res://a"]}),
        ) as ln:
            ln.wait_frames(1)
            time.sleep(0.3)  # let any (incorrect) background drive land
            assert _subscribe_calls(gateway_no_subscribe) == []

    def test_an_empty_or_absent_list_omits_the_field(self, gateway):
        for requested in ({RESOURCE_FIELD: []}, {"toolsListChanged": True}):
            with _Listener(gateway, _listen_body(notifications=requested)) as ln:
                ack = ln.wait_frames(1)[0]
            assert RESOURCE_FIELD not in ack["params"]["notifications"]

    def test_a_malformed_list_degrades_instead_of_crashing(self, gateway):
        """Relay hardened this exact read after a real incident: a nested
        list inside the URI array raised `TypeError: unhashable type` in a
        daemon thread and killed it (#358 review R2F1). Non-strings are
        dropped; a non-list is treated as absent."""
        with _Listener(
            gateway,
            _listen_body(
                notifications={RESOURCE_FIELD: ["res://a", ["nested"], 7, None]}
            ),
        ) as ln:
            ack = ln.wait_frames(1)[0]
        assert ack["params"]["notifications"][RESOURCE_FIELD] == ["res://a"]

        with _Listener(
            gateway, _listen_body("l2", notifications={RESOURCE_FIELD: "res://a"})
        ) as ln:
            ack = ln.wait_frames(1)[0]
        assert RESOURCE_FIELD not in ack["params"]["notifications"]

    def test_duplicate_uris_collapse(self, gateway):
        """Otherwise one stream could inflate a URI's refcount by
        repeating it, and the matching unsubscribe would never fire."""
        with _Listener(
            gateway,
            _listen_body(notifications={RESOURCE_FIELD: ["res://a", "res://a"]}),
        ) as ln:
            ack = ln.wait_frames(1)[0]
        assert ack["params"]["notifications"][RESOURCE_FIELD] == ["res://a"]

    def test_over_the_cap_truncates_and_honors_the_subset(self, gateway, monkeypatch):
        """Truncate-and-honor rather than refuse: the ack echoes exactly
        what is honored, so a client that checks it sees precisely which
        URIs it got — strictly more useful than an error the legacy
        `resources/subscribe` never had a shape for."""
        monkeypatch.setattr(server, "_LISTEN_MAX_RESOURCE_SUBSCRIPTIONS", 3)
        uris = [f"res://{i}" for i in range(10)]
        with _Listener(
            gateway, _listen_body(notifications={RESOURCE_FIELD: uris})
        ) as ln:
            ack = ln.wait_frames(1)[0]
        assert ack["params"]["notifications"][RESOURCE_FIELD] == uris[:3]

    def test_the_trio_and_uris_coexist_in_one_ack(self, gateway):
        """One `notifications` object carrying both shapes — booleans and
        a URI list — because that IS the wire shape the spec shows."""
        with _Listener(
            gateway,
            _listen_body(
                notifications={"toolsListChanged": True, RESOURCE_FIELD: ["res://a"]}
            ),
        ) as ln:
            ack = ln.wait_frames(1)[0]
        assert ack["params"]["notifications"] == {
            "toolsListChanged": True,
            RESOURCE_FIELD: ["res://a"],
        }


class TestResourceUpdateRouting:
    """One update, only to the streams that named that exact URI."""

    def test_an_update_reaches_the_subscribing_stream_stamped(self, gateway):
        with _Listener(
            gateway, _listen_body(notifications={RESOURCE_FIELD: ["res://a"]})
        ) as ln:
            ln.wait_frames(1)
            _fire_resource_update(gateway, "res://a")
            event = ln.wait_frames(2)[1]
        assert event["method"] == RESOURCE_UPDATED
        assert event["params"]["uri"] == "res://a"
        assert event["params"]["_meta"][SUBSCRIPTION_ID] == "listen-1"

    def test_an_unsubscribed_uri_is_not_delivered(self, gateway, quick_keepalive):
        """Per-URI, not per-field. Folding `resourceSubscriptions` into
        the boolean whitelist would make ANY non-empty list match every
        URI — the exact "MUST NOT send notification types the client has
        not explicitly requested" violation the whitelist exists for.

        Bounded by a keepalive, which proves the pump ran and chose to
        send nothing, rather than by a sleep.
        """
        with _Listener(
            gateway, _listen_body(notifications={RESOURCE_FIELD: ["res://a"]})
        ) as ln:
            ln.wait_frames(1)
            _fire_resource_update(gateway, "res://other")
            ln.wait_comments(2)
            frames, _ = ln.snapshot()
        assert len(frames) == 1, frames

    def test_two_streams_split_by_uri_not_by_field(self, gateway):
        """The cross-stream leak this branch exists to prevent, pinned
        directly: A and B share one pooled child, each subscribed to a
        different URI, and each must see only its own."""
        a = _Listener(
            gateway, _listen_body("a", notifications={RESOURCE_FIELD: ["res://a"]})
        )
        b = _Listener(
            gateway, _listen_body("b", notifications={RESOURCE_FIELD: ["res://b"]})
        )
        with a, b:
            a.wait_frames(1)
            b.wait_frames(1)
            _fire_resource_update(gateway, "res://a")
            event = a.wait_frames(2)[1]
            assert event["params"]["uri"] == "res://a"
            _fire_resource_update(gateway, "res://b")
            b_event = b.wait_frames(2)[1]
        assert b_event["params"]["uri"] == "res://b"
        # A never saw B's URI: exactly two frames, ack + its own update.
        a_frames, _ = a.snapshot()
        assert len(a_frames) == 2, a_frames

    def test_the_same_uri_fans_out_to_both_streams(self, gateway):
        """Multicast at the fan-out layer, N unicast frames at the wire —
        each carrying its OWN subscriptionId."""
        a = _Listener(
            gateway, _listen_body("a", notifications={RESOURCE_FIELD: ["res://s"]})
        )
        b = _Listener(
            gateway, _listen_body("b", notifications={RESOURCE_FIELD: ["res://s"]})
        )
        with a, b:
            a.wait_frames(1)
            b.wait_frames(1)
            _fire_resource_update(gateway, "res://s")
            a_event = a.wait_frames(2)[1]
            b_event = b.wait_frames(2)[1]
        assert a_event["params"]["_meta"][SUBSCRIPTION_ID] == "a"
        assert b_event["params"]["_meta"][SUBSCRIPTION_ID] == "b"

    def test_a_trio_only_stream_gets_no_resource_updates(
        self, gateway, quick_keepalive
    ):
        with _Listener(
            gateway, _listen_body(notifications={"toolsListChanged": True})
        ) as ln:
            ln.wait_frames(1)
            _fire_resource_update(gateway, "res://a")
            ln.wait_comments(2)
            frames, _ = ln.snapshot()
        assert len(frames) == 1, frames


class TestResourceSubscriptionUnits:
    """The honored-set computation, away from HTTP."""

    def test_the_capability_predicate_reads_presence_and_truthiness(self):
        supports = server._child_supports_resource_subscribe
        assert supports({"capabilities": {"resources": {"subscribe": True}}}) is True
        assert supports({"capabilities": {"resources": {"subscribe": False}}}) is False
        assert supports({"capabilities": {"resources": {}}}) is False
        assert supports({"capabilities": {}}) is False
        assert supports({}) is False
        # Degrades on malformed shapes rather than raising — a
        # misbehaving child forfeits the capability, never the request.
        assert supports({"capabilities": {"resources": True}}) is False
        assert supports({"capabilities": "nope"}) is False
        assert supports(None) is False

    def test_the_capability_gate_short_circuits_the_whole_computation(self):
        uris, truncated = server._honored_resource_uris(["res://a"], supported=False)
        assert uris == [] and truncated is False

    def test_first_seen_order_is_preserved(self):
        uris, _ = server._honored_resource_uris(
            ["res://b", "res://a", "res://b"], supported=True
        )
        assert uris == ["res://b", "res://a"]

    def test_truncation_is_reported_so_it_can_be_logged_once(self, monkeypatch):
        monkeypatch.setattr(server, "_LISTEN_MAX_RESOURCE_SUBSCRIPTIONS", 2)
        uris, truncated = server._honored_resource_uris(["a", "b", "c"], supported=True)
        assert uris == ["a", "b"] and truncated is True
        uris, truncated = server._honored_resource_uris(["a", "b"], supported=True)
        assert truncated is False

    def test_wants_resource_update_is_exact(self):
        """No normalization: trailing slash, case and percent-encoding are
        DIFFERENT subscriptions, deliberately (there is no child-side echo
        to normalize against)."""
        stream = server._ListenStream("x", {}, frozenset({"res://a"}))
        assert stream.wants_resource_update("res://a") is True
        assert stream.wants_resource_update("res://a/") is False
        assert stream.wants_resource_update("RES://A") is False
        assert stream.wants_resource_update(None) is False
        assert stream.wants_resource_update(7) is False


class TestResourceSubscriptionRefcounts:
    """The child is told once and untold once, however many streams ask.

    Every assertion here reads the child's own subscribe/unsubscribe call
    log. Absence-of-updates would pass just as happily when routing is
    broken or the feature is missing entirely, which is the vacuous
    observation this project keeps catching; a call log distinguishes
    "nothing was sent" from "nothing happened".
    """

    def _wait_calls(self, url, count, timeout=10.0):
        """The child's call log once it has at least `count` entries.

        Driving is asynchronous by design, so the log is polled to a bound
        rather than read once — but the assertion is still on the exact
        contents, never on "at least something arrived".
        """
        deadline = time.monotonic() + timeout
        calls: list = []
        while time.monotonic() < deadline:
            calls = _subscribe_calls(url)
            if len(calls) >= count:
                return calls
            time.sleep(0.02)
        return calls

    def test_the_full_lifecycle_across_two_streams(self, gateway):
        """§3.10's sequence, end to end: subscribe once, dedup, fan out,
        no early unsubscribe, unsubscribe exactly once at zero."""
        uri = "res://shared"
        first = _Listener(
            gateway, _listen_body("a", notifications={RESOURCE_FIELD: [uri]})
        )
        second = _Listener(
            gateway, _listen_body("b", notifications={RESOURCE_FIELD: [uri]})
        )

        with first:
            first.wait_frames(1)
            # (2) exactly one subscribe reached the child.
            assert self._wait_calls(gateway, 1) == [["resources/subscribe", uri]]

            with second:
                second.wait_frames(1)
                # (3) STILL exactly one: the second stream deduped. A
                # positive count, not "no new call was detected".
                time.sleep(0.3)
                assert _subscribe_calls(gateway) == [["resources/subscribe", uri]]

                # (4) one update, both streams, each with its own stamp.
                _fire_resource_update(gateway, uri)
                a_event = first.wait_frames(2)[1]
                b_event = second.wait_frames(2)[1]
                assert a_event["params"]["_meta"][SUBSCRIPTION_ID] == "a"
                assert b_event["params"]["_meta"][SUBSCRIPTION_ID] == "b"

            # (5)/(6) second stream gone, refcount 1: no unsubscribe yet,
            # and the survivor still receives.
            time.sleep(0.3)
            assert _subscribe_calls(gateway) == [["resources/subscribe", uri]]
            _fire_resource_update(gateway, uri)
            assert first.wait_frames(3)[2]["params"]["uri"] == uri

        # (7) last stream gone -> exactly one unsubscribe.
        calls = self._wait_calls(gateway, 2)
        assert calls == [
            ["resources/subscribe", uri],
            ["resources/unsubscribe", uri],
        ], calls

    def test_distinct_uris_are_refcounted_independently(self, gateway):
        with _Listener(
            gateway,
            _listen_body(notifications={RESOURCE_FIELD: ["res://x", "res://y"]}),
        ) as ln:
            ln.wait_frames(1)
            calls = self._wait_calls(gateway, 2)
        assert calls[:2] == [
            ["resources/subscribe", "res://x"],
            ["resources/subscribe", "res://y"],
        ]
        after = self._wait_calls(gateway, 4)
        assert sorted(c[1] for c in after if c[0] == "resources/unsubscribe") == [
            "res://x",
            "res://y",
        ]

    def test_an_abrupt_disconnect_still_unsubscribes(self, gateway):
        """Companion to the clean-detach path (§3.10 item 8): the same
        zero-refcount unsubscribe must fire when the client vanishes
        rather than closing politely."""
        uri = "res://abrupt"
        ln = _Listener(gateway, _listen_body(notifications={RESOURCE_FIELD: [uri]}))
        with ln:
            ln.wait_frames(1)
            assert self._wait_calls(gateway, 1) == [["resources/subscribe", uri]]
        calls = self._wait_calls(gateway, 2)
        assert ["resources/unsubscribe", uri] in calls, calls

    def test_a_failing_subscribe_keeps_the_uri_honored(self, gateway, monkeypatch):
        """Reply-then-degrade: the ack has already shipped, and a timeout
        does not say whether the child processed the request. The URI
        keeps its refcount so the matching unsubscribe still fires."""
        monkeypatch.setattr(server, "_BACKEND_RESPONSE_TIMEOUT_SECS", 0.3)
        uri = "res://noreply"
        # `noreply` is the fake child's documented silent method; routing
        # the subscribe at it makes the drive time out for real.
        original = server.BackendProcess._drive_resource_subscription

        def _timing_out(self, method, u):
            if method == "resources/subscribe":
                return False
            return original(self, method, u)

        monkeypatch.setattr(
            server.BackendProcess, "_drive_resource_subscription", _timing_out
        )
        with _Listener(
            gateway, _listen_body(notifications={RESOURCE_FIELD: [uri]})
        ) as ln:
            ack = ln.wait_frames(1)[0]
            # Still honored in the ack despite the failed drive.
            assert ack["params"]["notifications"][RESOURCE_FIELD] == [uri]
            _fire_resource_update(gateway, uri)
            # And still ROUTED — honoring is what routing reads, not
            # whether the child confirmed.
            assert ln.wait_frames(2)[1]["params"]["uri"] == uri

    def test_the_refs_die_with_the_child(self, gateway):
        """No explicit clear-on-death step exists, deliberately: the map
        lives on the `BackendProcess`, so a respawn gets an empty one for
        free. Pinned so a future edit cannot quietly add a second source
        of truth."""
        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        try:
            backend.add_resource_subscriptions(["res://a"], "l1")
            # (count, driven) — #388 review R2F1. The real fake backend
            # answers resources/subscribe, so this URI is both referenced
            # and actually driven.
            assert backend._resource_refs == {"res://a": (1, True)}
        finally:
            backend.shutdown()
        # A fresh child starts clean — the state is object-scoped.
        replacement = server.BackendProcess([*_BACKEND], modern_owned=True)
        try:
            assert replacement._resource_refs == {}
        finally:
            replacement.shutdown()


def test_a_stream_torn_down_before_its_subscribe_lands_leaves_nothing_behind():
    """The ordering race between the async drive and the sync release.

    Driving is asynchronous, so a client that disconnects immediately
    after the ack can have its teardown run BEFORE its subscribe. Without
    the `torn_down` handshake the two invert: release finds no reference
    and does nothing, then the drive subscribes — and the child stays
    subscribed forever with no stream to deliver to.

    Revert-check: drop the `torn_down` guard from
    `add_resource_subscriptions` and this leaves `res://late` refcounted
    with a live subscribe on the child.
    """
    backend = server.BackendProcess([*_BACKEND], modern_owned=True)
    try:
        listener = server._ListenStream("late", {}, frozenset({"res://late"}))
        # Teardown wins the race.
        listener.torn_down = True
        backend.release_resource_subscriptions(["res://late"])
        backend.add_resource_subscriptions(["res://late"], "late", listener)
        assert backend._resource_refs == {}
    finally:
        backend.shutdown()


class TestResourceSubscribeDriveIsBounded:
    """A hung child must not hold `_sub_lock` for hours (#388 review).

    The lock is held across the drive on purpose — it is what keeps
    subscribe and unsubscribe from inverting on the wire — but that same
    lock is what every OTHER stream's teardown blocks on. At the ordinary
    120 s backend timeout, 256 URIs against an unresponsive child would
    pin it for 8.5 hours.
    """

    def test_the_drive_uses_its_own_short_timeout(self):
        """Pinned as a RELATIONSHIP, not a literal: what matters is that
        this path is bounded far below the general backend timeout, so a
        later bump of that constant cannot silently re-create the stall.

        Revert-check: pass `_BACKEND_RESPONSE_TIMEOUT_SECS` here again and
        this fails.
        """
        assert server._RESOURCE_SUBSCRIBE_TIMEOUT_SECS < (
            server._BACKEND_RESPONSE_TIMEOUT_SECS / 10
        )
        seen: list[float] = []
        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        original = backend.send_request

        def _record(line, req_id, timeout):
            seen.append(timeout)
            return original(line, req_id, timeout)

        backend.send_request = _record  # type: ignore[method-assign]
        try:
            backend.add_resource_subscriptions(["res://a"], "l1")
        finally:
            backend.shutdown()
        assert seen == [server._RESOURCE_SUBSCRIBE_TIMEOUT_SECS]

    def test_an_unresponsive_child_is_not_hammered_once_per_uri(self, monkeypatch):
        """One timeout for the batch, not one per URI — the difference
        between seconds and hours of held lock.

        Every URI still keeps its reference: the ack already promised
        them, and reply-then-degrade says a subscription that never fires
        is still honored.
        """
        calls: list[str] = []

        def _never_answers(self, method, uri):
            calls.append(uri)
            return None

        monkeypatch.setattr(
            server.BackendProcess, "_drive_resource_subscription", _never_answers
        )
        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        try:
            uris = [f"res://{i}" for i in range(10)]
            backend.add_resource_subscriptions(uris, "l1")
            assert calls == ["res://0"], calls
            assert len(backend._resource_refs) == 10
        finally:
            backend.shutdown()

    def test_the_teardown_path_short_circuits_too(self, monkeypatch):
        """This one matters more: `release` runs in the handler's
        `finally`, so an unbounded loop there holds the handler THREAD as
        well as the lock."""
        calls: list[str] = []

        def _never_answers(self, method, uri):
            calls.append(f"{method}:{uri}")
            return None

        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        try:
            uris = [f"res://{i}" for i in range(10)]
            backend.add_resource_subscriptions(uris, "l1")
            monkeypatch.setattr(
                server.BackendProcess, "_drive_resource_subscription", _never_answers
            )
            backend.release_resource_subscriptions(uris)
            assert calls == ["resources/unsubscribe:res://0"], calls
            # The refs are dropped regardless — they die with the child
            # anyway, and keeping them would leak across a respawn.
            assert backend._resource_refs == {}
        finally:
            backend.shutdown()

    def test_an_error_reply_does_not_stop_the_batch(self):
        """Only silence short-circuits. An error means the child is ALIVE
        and answered about that URI, which says nothing about the next
        one — treating it as unresponsive would silently skip
        subscriptions a healthy child would have accepted."""
        seen: list[str] = []

        class _Erroring(server.BackendProcess):
            def _drive_resource_subscription(self, method, uri):
                seen.append(uri)
                return False

        backend = _Erroring([*_BACKEND], modern_owned=True)
        try:
            backend.add_resource_subscriptions(["res://a", "res://b"], "l1")
            assert seen == ["res://a", "res://b"]
        finally:
            backend.shutdown()


def _selective_recorder(calls: list, *, times_out: frozenset):
    """A `_drive_resource_subscription` stand-in: any URI in `times_out`
    returns `None` (the child never answers); everything else returns
    `True` (a real success) — WHEN it is actually asked. Every call is
    recorded in `calls` as `(method, uri)`, which is the wire evidence
    these tests assert on (this file's own precedent, see
    `_subscribe_calls`'s docstring): whether the request actually
    reached the child, not whether an update later showed up.
    """

    def _drive(self, method, uri):
        calls.append((method, uri))
        return None if uri in times_out else True

    return _drive


class TestResourceSubscriptionDrivenTracking:
    """#388 review R2F1 — a refcount must not conflate "referenced" with
    "successfully driven".

    `add_resource_subscriptions` used a plain `int` refcount: `count > 0`
    meant both "a stream claims this URI" AND "the child was told",
    which are not the same claim. A batch whose first URI times out
    stops driving the REST of that batch (the existing, correct
    `responsive` short-circuit — see `TestResourceSubscribeDriveIsBounded`)
    but the refcount for every later first-reference URI in that batch
    still went to 1, indistinguishable from a URI that really was
    subscribed. No LATER call — a different stream, possibly against a
    since-recovered child — could ever tell the two apart, so the gap
    was permanent.
    """

    def test_a_batch_timeout_leaves_a_later_uri_undriven_not_subscribed(
        self, monkeypatch
    ):
        """The sticky's exact reproduction. `res://slow` (first in the
        batch) never answers, so `responsive` flips False and
        `res://healthy` (second) never gets a drive attempt at all —
        wire evidence: `calls` has no entry for it. That URI must be
        left marked UNDRIVEN, not silently treated as subscribed.
        """
        calls: list[tuple[str, str]] = []
        monkeypatch.setattr(
            server.BackendProcess,
            "_drive_resource_subscription",
            _selective_recorder(calls, times_out=frozenset({"res://slow"})),
        )
        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        try:
            backend.add_resource_subscriptions(["res://slow", "res://healthy"], "l1")
            assert calls == [("resources/subscribe", "res://slow")], calls
            # res://slow WAS driven — an attempt reached the wire, even
            # though the reply never came back.
            assert backend._resource_refs["res://slow"] == (1, True)
            # res://healthy was only ever refcounted; nothing was sent.
            assert backend._resource_refs["res://healthy"] == (1, False), (
                "an undriven URI must not be marked as subscribed"
            )
        finally:
            backend.shutdown()

    def test_an_undriven_uri_is_retried_by_a_later_call(self, monkeypatch):
        """The fix's whole point: once something asks about `res://healthy`
        again — a different stream, the child now answering — the drive
        must be RE-ATTEMPTED, not skipped as "already subscribed".

        Wire evidence, not absence-of-updates: asserts the child actually
        RECEIVES a second `resources/subscribe` for `res://healthy`.

        Revert-check: restore the single-int refcount and the `if count:
        continue` skip (drop the `driven` tracking) — the second call
        never reaches `calls`, because a plain positive count already
        reads as "subscribed".
        """
        calls: list[tuple[str, str]] = []
        monkeypatch.setattr(
            server.BackendProcess,
            "_drive_resource_subscription",
            _selective_recorder(calls, times_out=frozenset({"res://slow"})),
        )
        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        try:
            # First stream: the batch that leaves res://healthy undriven
            # — the undriven state itself is pinned by the sibling test
            # above; this one only needs it to set up the retry.
            backend.add_resource_subscriptions(["res://slow", "res://healthy"], "l1")
            calls.clear()

            # Second stream, later: only res://healthy, child responsive
            # this time (nothing here times out).
            backend.add_resource_subscriptions(["res://healthy"], "l2")

            assert calls == [("resources/subscribe", "res://healthy")], calls
            assert backend._resource_refs["res://healthy"] == (2, True)
        finally:
            backend.shutdown()

    def test_release_skips_the_unsubscribe_for_an_undriven_uri(self, monkeypatch):
        """The mirror bug, on the release side. A URI whose refcount
        reaches zero without ever having been driven has nothing on the
        child to undo — sending `resources/unsubscribe` anyway would be
        serve inventing traffic for a subscribe that never happened.

        Revert-check: restore the plain-int refcount (which drives
        `resources/unsubscribe` unconditionally once count hits zero,
        with no driven check) — a spurious unsubscribe reaches the
        child for `res://healthy`.
        """
        calls: list[tuple[str, str]] = []
        monkeypatch.setattr(
            server.BackendProcess,
            "_drive_resource_subscription",
            _selective_recorder(calls, times_out=frozenset({"res://slow"})),
        )
        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        try:
            # The undriven state itself is pinned by the first test in
            # this class; this one only needs it to set up the release.
            backend.add_resource_subscriptions(["res://slow", "res://healthy"], "l1")
            calls.clear()

            backend.release_resource_subscriptions(["res://healthy"])

            assert calls == [], calls
            assert "res://healthy" not in backend._resource_refs
        finally:
            backend.shutdown()


def _erroring_recorder(calls: list):
    """A `_drive_resource_subscription` stand-in that always answers with
    an ERROR reply (`False`, not `None`) — the child is alive and
    responding, it just declines every URI. Records every call, same
    wire-evidence idiom as `_selective_recorder`.
    """

    def _drive(self, method, uri):
        calls.append((method, uri))
        return False

    return _drive


class TestResourceSubscribeFailureLogThrottle:
    """#388 review — the "did not confirm subscribe" log needs a
    once-per-stream latch, mirroring `listen {req_id!r}: capped resource
    subscriptions...`'s own once-per-stream posture and relay's
    `unhonored_logged` idiom (the two are the closest existing precedent
    in this codebase; neither is byte-for-byte what's built here — see
    the docstring on `subscribe_failure_logged`).

    Today's only call site drives a URI at most ONCE per stream, so a
    natural end-to-end scenario cannot make the same URI fail twice for
    one stream — proven below by driving it through the one legitimate
    mechanism that CAN re-drive a URI within a stream (release, then a
    fresh reference), and asserting the wire evidence shows two drive
    attempts but the log fires only once. This is deliberately not a
    "many distinct URIs in one batch" test: that case is UNAFFECTED by
    this fix on purpose (per-URI granularity is kept — each of N
    different failing URIs still gets its own line).
    """

    def test_a_uri_re_driven_within_one_stream_logs_only_once(self, monkeypatch):
        """Revert-check: remove the `subscribe_failure_logged` latch
        (log unconditionally on every `not outcome`) — this test then
        sees TWO log lines instead of one, because the release-then-
        re-add below genuinely re-drives the URI and, without the
        latch, re-logs it too.
        """
        calls: list[tuple[str, str]] = []
        logged: list[str] = []
        monkeypatch.setattr(
            server.BackendProcess,
            "_drive_resource_subscription",
            _erroring_recorder(calls),
        )
        monkeypatch.setattr(server, "log", lambda msg: logged.append(msg))

        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        listener = server._ListenStream("l1", {}, frozenset({"res://err"}))
        try:
            backend.add_resource_subscriptions(["res://err"], "l1", listener)
            assert calls == [("resources/subscribe", "res://err")], calls
            assert len(logged) == 1, logged

            # The only legitimate way to re-drive a URI within one
            # stream's life: it is released (refcount to zero, entry
            # popped — same listener, same `subscribe_failure_logged`
            # set, which is NOT cleared by release) and then referenced
            # again by the same stream.
            backend.release_resource_subscriptions(["res://err"])
            backend.add_resource_subscriptions(["res://err"], "l1", listener)

            # Wire evidence: the drive really did happen a SECOND time.
            assert calls == [
                ("resources/subscribe", "res://err"),
                ("resources/unsubscribe", "res://err"),
                ("resources/subscribe", "res://err"),
            ], calls
            # But the failure log did not fire again for this stream.
            assert len(logged) == 1, logged
        finally:
            backend.shutdown()

    def test_a_different_stream_gets_its_own_log(self, monkeypatch):
        """The latch is per-STREAM (the listener object), not global —
        once `res://err` is fully released by stream `l1` (its own
        teardown) and a SECOND, independent stream `l2` subscribes to it
        fresh, that is a genuinely new drive, and it logs its OWN line
        into its OWN `subscribe_failure_logged`. Matches the
        cap-truncation log's own documented scope ("a client that blew
        the cap will blow it on every reconnect") — the throttle resets
        per stream, it does not remember a URI's failure forever.

        (Two streams BOTH holding a live reference to the same URI
        cannot be used to show this: the second would see `driven=True`
        from the first's attempt and never drive at all — see the
        sibling re-drive test's docstring. Release is what makes the
        second attempt real.)
        """
        calls: list[tuple[str, str]] = []
        logged: list[str] = []
        monkeypatch.setattr(
            server.BackendProcess,
            "_drive_resource_subscription",
            _erroring_recorder(calls),
        )
        monkeypatch.setattr(server, "log", lambda msg: logged.append(msg))

        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        first = server._ListenStream("l1", {}, frozenset({"res://err"}))
        second = server._ListenStream("l2", {}, frozenset({"res://err"}))
        try:
            backend.add_resource_subscriptions(["res://err"], "l1", first)
            backend.release_resource_subscriptions(["res://err"])  # l1 tears down
            backend.add_resource_subscriptions(["res://err"], "l2", second)

            assert calls == [
                ("resources/subscribe", "res://err"),
                ("resources/unsubscribe", "res://err"),
                ("resources/subscribe", "res://err"),
            ], calls
            assert len(logged) == 2, logged
            assert "res://err" in first.subscribe_failure_logged
            assert "res://err" in second.subscribe_failure_logged
        finally:
            backend.shutdown()

    def test_many_distinct_uris_in_one_batch_each_still_get_their_own_line(self):
        """The latch does NOT throttle a large batch of DIFFERENT URIs —
        per-URI granularity is kept on purpose (still worth knowing
        WHICH URIs failed). This is the scenario the finding's "256
        lines" example describes, and the fix leaves it unchanged.
        """

        class _AlwaysErrors(server.BackendProcess):
            def _drive_resource_subscription(self, method, uri):
                return False

        backend = _AlwaysErrors([*_BACKEND], modern_owned=True)
        listener = server._ListenStream(
            "l1", {}, frozenset({"res://0", "res://1", "res://2"})
        )
        try:
            backend.add_resource_subscriptions(
                ["res://0", "res://1", "res://2"], "l1", listener
            )
            assert listener.subscribe_failure_logged == {
                "res://0",
                "res://1",
                "res://2",
            }
        finally:
            backend.shutdown()


# --- reverse MRTR: the signed pointer (#375 PR 1) -------------------------


class TestMrtrPointer:
    """`requestState` is a signed POINTER, not a state container.

    The distinction is the design's central correction and worth stating
    in a test file too: what a retry resumes is a live subprocess blocked
    on its own stdin read, which no amount of embedded state can
    un-block from another process. So this blob carries only enough to
    find an entry in the child's own table and prove entitlement to it.
    """

    def test_a_minted_pointer_round_trips(self):
        state = server._mrtr_encode_pointer("txn-1", "alice", 1)
        payload, why = server._mrtr_decode_pointer(state, "alice")
        assert why == ""
        assert payload["txn_id"] == "txn-1"
        assert payload["round"] == 1
        assert payload["v"] == server._MRTR_POINTER_VERSION

    def test_the_raw_principal_never_appears_in_the_blob(self):
        """The client holds this value and the spec only forbids it from
        PARSING it — which is not a security control. A hash binds the
        pointer just as well, since the only operation ever performed on
        it is equality against a freshly-resolved principal."""
        state = server._mrtr_encode_pointer("txn-1", "alice@example.com", 1)
        assert "alice" not in server._b64url_decode(state.split(".")[0]).decode()

    def test_the_principal_tag_depends_on_the_key_not_just_the_string(self):
        """#389 review, score 85: `_mrtr_principal_hash` used to be a bare
        `sha256` of the principal string — a "non-reversible tag" only in
        name, since it mixed in no secret. `requestState`'s payload is
        integrity-protected, not encrypted, and the spec's confidentiality
        obligation runs the OTHER way ("clients MUST NOT inspect ... its
        contents", not "servers must keep it secret") — so a proxy log, a
        client-side debug dump, or a support screenshot can expose this
        tag. OAuth principals are low-entropy and guessable (usernames,
        emails), so an UNKEYED hash would let anyone holding a leaked
        blob run an offline dictionary attack: hash every guessed
        principal, compare, learn who opened the round.

        Simulates exactly that attacker — someone who can read the tag
        but does not have `_MRTR_POINTER_KEY` — by recomputing the OLD,
        unkeyed formula directly and asserting it does NOT match what the
        real function produces for the same guessable strings.

        Revert-check: swap `_mrtr_principal_hash` back to the bare
        `hashlib.sha256` call and this assertion flips to a match — the
        attacker's guess-and-compare would have worked.
        """
        for guessable in ("alice@example.com", "bob@example.com"):
            real_tag = server._mrtr_principal_hash(guessable)
            attacker_guess = hashlib.sha256(
                f"mcp-stdio/mrtr/{guessable!r}".encode()
            ).hexdigest()
            assert real_tag != attacker_guess, guessable

    def test_a_tampered_payload_is_rejected(self):
        """O14: "servers MUST ... reject state that fails verification".

        Every byte of the payload is flipped in turn, so this cannot pass
        by happening to mutate a field nothing reads.

        Mutating the DECODED BYTES and re-encoding, not the base64 text
        (#389 review): unpadded base64's final character carries unused
        bits, so a text-level flip there can decode to the identical
        bytes, verify fine, and make this assertion wrong for reasons
        that have nothing to do with the property under test.

        Revert-check: drop the `compare_digest` check and this fails.
        """
        state = server._mrtr_encode_pointer("txn-1", "alice", 1)
        raw_b64, mac_b64 = state.split(".")
        raw = server._b64url_decode(raw_b64)
        for i in range(len(raw)):
            mutated = bytearray(raw)
            mutated[i] ^= 0x01
            tampered = f"{server._b64url(bytes(mutated))}.{mac_b64}"
            payload, why = server._mrtr_decode_pointer(tampered, "alice")
            assert payload is None, (i, tampered)
            assert why, i

    def test_a_tampered_mac_is_rejected(self):
        state = server._mrtr_encode_pointer("txn-1", "alice", 1)
        raw_b64, mac_b64 = state.split(".")
        flipped = ("A" if mac_b64[0] != "A" else "B") + mac_b64[1:]
        assert server._mrtr_decode_pointer(f"{raw_b64}.{flipped}", "alice")[0] is None

    def test_a_pointer_for_another_principal_is_rejected(self):
        """Defense in depth beyond the pool's per-principal keying: a
        GENUINE pointer that leaked between users is exactly the case
        pool keying alone does not cover."""
        state = server._mrtr_encode_pointer("txn-1", "alice", 1)
        payload, why = server._mrtr_decode_pointer(state, "bob")
        assert payload is None
        assert "principal" in why

    def test_an_expired_pointer_is_rejected(self):
        state = server._mrtr_encode_pointer("txn-1", "alice", 1, now=1000.0)
        assert server._mrtr_decode_pointer(state, "alice", now=1000.0)[0] is not None
        payload, why = server._mrtr_decode_pointer(
            state, "alice", now=1000.0 + server._MRTR_POINTER_TTL_SECS + 1
        )
        assert payload is None and "expired" in why

    def test_every_malformed_shape_returns_a_reason_rather_than_raising(self):
        """This parses attacker-controlled input on a request-handling
        path, so a raise here is a crash in a handler thread."""
        for bad in (
            None,
            7,
            "",
            "no-dot",
            "a.b.c",
            "!!!.!!!",
            "....",
            f"{server._b64url(b'not json')}.{server._b64url(b'x')}",
        ):
            payload, why = server._mrtr_decode_pointer(bad, "alice")
            assert payload is None, bad
            assert why, bad

    def test_a_forged_payload_cannot_be_signed_without_the_key(self):
        """The whole point of the MAC: a client that understands the
        format still cannot mint one."""
        forged = server._mrtr_pointer_payload_bytes(
            {
                "v": 1,
                "txn_id": "attacker",
                "principal": server._mrtr_principal_hash("alice"),
                "round": 1,
                "issued_at": 0.0,
                "expires_at": 1e12,
            }
        )
        state = f"{server._b64url(forged)}.{server._b64url(b'whatever')}"
        assert server._mrtr_decode_pointer(state, "alice")[0] is None

    def test_the_round_rides_inside_the_signature(self):
        """Serve keeps no per-client round counter across requests, so
        the count is only trustworthy because it is signed — otherwise a
        client resets its own cap by hand-crafting `round: 1`."""
        state = server._mrtr_encode_pointer("txn-1", "alice", 5)
        assert server._mrtr_decode_pointer(state, "alice")[0]["round"] == 5
        raw = json.loads(server._b64url_decode(state.split(".")[0]))
        raw["round"] = 1
        rewritten = server._mrtr_pointer_payload_bytes(raw)
        forged = f"{server._b64url(rewritten)}.{state.split('.')[1]}"
        assert server._mrtr_decode_pointer(forged, "alice")[0] is None

    def test_a_round_beyond_the_cap_is_rejected(self):
        """Enforced at the DECODER, not only wherever the next round is
        opened (#389 review). The decoder is what decides a pointer is
        valid at all, so a mint-side regression cannot hand out one that
        outlives the cap.

        Revert-check: drop the `> _MRTR_MAX_ROUNDS` check and this
        returns a valid payload.
        """
        ok = server._mrtr_encode_pointer("t", "alice", server._MRTR_MAX_ROUNDS)
        assert server._mrtr_decode_pointer(ok, "alice")[0] is not None
        too_far = server._mrtr_encode_pointer("t", "alice", server._MRTR_MAX_ROUNDS + 1)
        payload, why = server._mrtr_decode_pointer(too_far, "alice")
        assert payload is None
        assert "round" in why

    def test_a_bogus_round_value_is_rejected(self):
        for bad_round in (0, -1, "1", True, None):
            payload = {
                "v": 1,
                "txn_id": "t",
                "principal": server._mrtr_principal_hash("alice"),
                "round": bad_round,
                "issued_at": 0.0,
                "expires_at": 1e12,
            }
            raw = server._mrtr_pointer_payload_bytes(payload)
            mac = hmac.new(server._MRTR_POINTER_KEY, raw, hashlib.sha256).digest()
            state = f"{server._b64url(raw)}.{server._b64url(mac)}"
            assert server._mrtr_decode_pointer(state, "alice")[0] is None, bad_round

    def test_the_key_is_process_lifetime_and_never_persisted(self):
        """A restart losing in-flight rounds is CORRECT, not a shortcut:
        a persisted key would let a client present a perfectly-signed
        pointer to a txn that provably cannot exist any more, turning an
        honest "unknown or expired" error into a silent misroute."""
        assert isinstance(server._MRTR_POINTER_KEY, bytes)
        assert len(server._MRTR_POINTER_KEY) == 32
        # A source-text scan used to stand in for "never persisted"
        # (#389 review): it was brittle against any refactor and did not
        # actually prove the property, since a key can be written out
        # from anywhere. The real guarantee is structural — the key is a
        # module-level `secrets.token_bytes` with no writer — and the
        # observable consequence is pinned by the round-trip tests, which
        # would fail if the key were ever reloaded rather than kept.


class TestMrtrParkedRoundTable:
    """The per-child table that is the single source of truth for a round.

    Nothing in PR 1 opens a round on a live path, so every method here is
    exercised directly and the table stays permanently empty in
    production — which is what makes this PR behaviour-inert.
    """

    def _backend(self):
        return server.BackendProcess([*_BACKEND], modern_owned=True)

    def test_a_parked_round_is_findable_by_its_txn_id(self):
        backend = self._backend()
        try:
            txn = backend.mrtr_round_open(
                "mcp-stdio/serve/1",
                method="elicitation/create",
                child_request_id="child-1",
                declared_caps={"elicitation": {}},
                principal="alice",
            )
            found = backend.mrtr_round_for_txn(txn)
            assert found is not None
            upstream_id, entry = found
            assert upstream_id == "mcp-stdio/serve/1"
            assert entry["child_request_id"] == "child-1"
            assert entry["round"] == 1
        finally:
            backend.shutdown()

    def test_the_txn_id_is_not_guessable(self):
        """It rides inside a client-held blob. Guessing is not sufficient
        to USE a round — the pointer still needs a valid MAC — but there
        is no reason to hand out the first factor for free."""
        backend = self._backend()
        try:
            seen = {
                backend.mrtr_round_open(
                    f"u{i}",
                    method="roots/list",
                    child_request_id=i,
                    declared_caps={},
                    principal="alice",
                )
                for i in range(50)
            }
            assert len(seen) == 50
            assert all(len(t) >= 16 for t in seen)
        finally:
            backend.shutdown()

    def test_consume_is_single_use(self):
        """The replay closure. HMAC stops forgery but not the re-sending
        of a genuine, still-validly-signed blob after its round finished;
        removing the entry is what makes the second attempt find nothing.

        Revert-check: make `mrtr_round_consume` a lookup that does not
        pop, and the second call starts succeeding.
        """
        backend = self._backend()
        try:
            txn = backend.mrtr_round_open(
                "u1",
                method="sampling/createMessage",
                child_request_id="c1",
                declared_caps={},
                principal="alice",
            )
            first = backend.mrtr_round_consume(txn)
            assert first is not None and first["upstream_id"] == "u1"
            assert backend.mrtr_round_consume(txn) is None
            assert backend.mrtr_round_for_txn(txn) is None
        finally:
            backend.shutdown()

    def test_two_concurrent_consumers_cannot_both_win(self):
        """Pop-and-read under one lock hold, so a racing pair of retries
        resolves to exactly one winner rather than both proceeding."""
        backend = self._backend()
        try:
            txn = backend.mrtr_round_open(
                "u1",
                method="roots/list",
                child_request_id="c1",
                declared_caps={},
                principal="alice",
            )
            results: list = []
            barrier = threading.Barrier(8)

            def _race():
                barrier.wait()
                results.append(backend.mrtr_round_consume(txn))

            threads = [threading.Thread(target=_race) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
            assert sum(1 for r in results if r is not None) == 1, results
        finally:
            backend.shutdown()

    def test_has_pending_is_the_concurrency_invariant_read(self):
        backend = self._backend()
        try:
            assert backend.mrtr_has_pending() is False
            txn = backend.mrtr_round_open(
                "u1",
                method="roots/list",
                child_request_id="c1",
                declared_caps={},
                principal="alice",
            )
            assert backend.mrtr_has_pending() is True
            backend.mrtr_round_consume(txn)
            assert backend.mrtr_has_pending() is False
        finally:
            backend.shutdown()

    def test_a_round_past_its_deadline_expires(self):
        backend = self._backend()
        try:
            backend.mrtr_round_open(
                "u1",
                method="roots/list",
                child_request_id="c1",
                declared_caps={},
                principal="alice",
                now=1000.0,
            )
            # Still inside the window.
            assert backend.mrtr_expire_parked(now=1000.0) == []
            assert backend.mrtr_has_pending() is True
            expired = backend.mrtr_expire_parked(
                now=1000.0 + server._MRTR_PARK_TIMEOUT_SECS + 1
            )
            assert [e["child_request_id"] for e in expired] == ["c1"]
            assert backend.mrtr_has_pending() is False
        finally:
            backend.shutdown()

    def test_abandonment_is_logged_once_per_transaction_not_per_poll(self, capsys):
        """#375 §4 Q7 trap 3 — the log-flood class.

        Expiry is checked on a POLL, so a line emitted while the entry
        SURVIVES would repeat once per tick for as long as it lasted.
        Here the entry is removed in the same lock hold that logs it, so
        the second sweep finds nothing to say.

        Asserted as a COUNT, since "the log looked fine" is exactly the
        observation this class of finding hides behind.

        Revert-check that BITES: make expiry non-popping (leave the entry
        in place) and this floods. A revert-check on the latch flag that
        was originally written here did NOT bite — the unconditional pop
        already guaranteed once-per-txn, so the flag was dead code and
        this test could not tell the difference. The flag is gone; the
        property it was supposed to protect is what is pinned.
        """
        backend = self._backend()
        try:
            backend.mrtr_round_open(
                "u1",
                method="roots/list",
                child_request_id="c1",
                declared_caps={},
                principal="alice",
                now=1000.0,
            )
            capsys.readouterr()
            late = 1000.0 + server._MRTR_PARK_TIMEOUT_SECS + 1
            for _ in range(5):
                backend.mrtr_expire_parked(now=late)
            assert capsys.readouterr().err.count("abandoned after") == 1
        finally:
            backend.shutdown()

    def test_the_park_timeout_is_a_ratio_not_a_literal(self):
        """#388's review found this exact class of ratio silently rotting
        when the general constant is bumped, so the RELATIONSHIP is what
        gets pinned.

        And the relationship is the load-bearing one: the dispatch
        timeout belongs to the original handler thread, which is already
        gone by the time a round is parked — so a park timeout at or
        above it would never fire before the child was abandoned anyway.
        """
        assert server._MRTR_PARK_TIMEOUT_SECS < server._BACKEND_RESPONSE_TIMEOUT_SECS
        assert server._MRTR_PARK_TIMEOUT_SECS > 0

    def test_the_table_dies_with_the_child(self):
        """No clear-on-death path exists, deliberately: the table lives on
        the `BackendProcess`, so a respawn gets an empty one for free —
        the same lifetime discipline `_resource_refs` established."""
        backend = self._backend()
        try:
            backend.mrtr_round_open(
                "u1",
                method="roots/list",
                child_request_id="c1",
                declared_caps={},
                principal="alice",
            )
            assert backend.mrtr_has_pending() is True
        finally:
            backend.shutdown()
        replacement = self._backend()
        try:
            assert replacement.mrtr_has_pending() is False
        finally:
            replacement.shutdown()


@pytest.fixture()
def gateway_with_pool():
    """A gateway that also hands back its `ModernBackendPool`.

    These tests must SEED a parked round, because PR 1 has nothing that
    opens one — that is the point of the PR. The ordinary `gateway`
    fixture yields only a URL, and reaching the pool by scanning live
    objects would be non-deterministic the moment another test's gateway
    exists, so the handle is passed explicitly.
    """
    httpd, registry = server.build_server(_BACKEND, host="127.0.0.1", port=0)
    host, port = httpd.server_address[0], httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}/mcp", httpd.modern_pool
    finally:
        httpd.shutdown()
        registry.shutdown_all()
        httpd.modern_pool.shutdown_all()
        httpd.server_close()


class TestMrtrEligibility:
    """Who may open a round, and the invariant that keeps it correlatable."""

    def test_only_a_genuine_oauth_principal_is_eligible(self):
        """#375 §4 Q1 — a SCOPE BOUNDARY, not a TODO.

        Principal binding is what stops one caller answering another's
        prompt, and it buys nothing when the principal is a shared
        constant: under no-auth the pool hands ONE child to every caller,
        and a static token does the same, so a prompt raised by caller
        A's request could be answered by whoever's retry lands next.
        """
        assert server._mrtr_principal_is_eligible("alice@example.com") is True
        # The open gateway.
        assert server._mrtr_principal_is_eligible(None) is False
        # The shared static-token constant — read from serve's own
        # definition rather than restated, so a rename cannot leave this
        # test asserting against a string nothing produces any more.
        assert server._mrtr_principal_is_eligible(server._STATIC_PRINCIPAL) is False

    def test_only_the_o14_methods_can_open_a_round(self):
        assert server._MRTR_ELIGIBLE_METHODS == {
            "tools/call",
            "resources/read",
            "prompts/get",
        }
        for never in ("tools/list", "server/discover", "subscriptions/listen"):
            assert never not in server._MRTR_ELIGIBLE_METHODS

    def test_a_busy_child_rejects_a_second_eligible_call(self, gateway_with_pool):
        """§1.2's invariant, driven through the real dispatch path.

        A bare legacy out-of-band request carries NO field linking it
        back to whichever in-flight call provoked it, so with two
        eligible calls on one shared child the correlation is genuinely
        ambiguous. The table is seeded directly because PR 1 opens no
        rounds — that is the point of the PR — and seeding is what lets
        the guard be tested before the thing that populates it exists.

        Revert-check: drop the `mrtr_has_pending()` guard from
        `_dispatch_modern` and this returns 200.
        """
        url, pool = gateway_with_pool
        backend, _, entry = pool.get_or_create(None)
        try:
            txn = backend.mrtr_round_open(
                "u1",
                method="tools/call",
                child_request_id="c1",
                declared_caps={},
                principal="alice",
            )
            resp = _post(
                url,
                _modern_body(
                    "tools/call",
                    params={"name": "echo_tool", "arguments": {}},
                    meta=_meta(),
                ),
                _modern_headers("tools/call", name="echo_tool"),
            )
            assert resp.status_code == 503, resp.text
            assert resp.json()["error"]["code"] == -32603
            assert "input-required" in resp.json()["error"]["message"]
        finally:
            backend.mrtr_round_consume(txn)
            pool.release(entry)

    def test_a_non_eligible_method_is_unaffected_by_a_parked_round(
        self, gateway_with_pool
    ):
        """The guard is scoped to the three O14 methods: a parked round
        must not stall `tools/list` for everyone on that child."""
        url, pool = gateway_with_pool
        backend, _, entry = pool.get_or_create(None)
        try:
            txn = backend.mrtr_round_open(
                "u1",
                method="tools/call",
                child_request_id="c1",
                declared_caps={},
                principal="alice",
            )
            resp = _post(
                url, _modern_body("tools/list", meta=_meta()), _modern_headers()
            )
            assert resp.status_code == 200, resp.text
        finally:
            backend.mrtr_round_consume(txn)
            pool.release(entry)


def test_pr1_opens_no_rounds_on_any_live_path(gateway_with_pool):
    """The zero-behaviour-change claim, asserted rather than argued.

    PR 1 builds the envelope, the table and the invariant; PR 2 wires
    them to actual traffic. If any live path started parking a round, the
    concurrency guard above would begin rejecting ordinary concurrent
    calls — an observable change this PR promises not to make.

    Drives one of each eligible method plus a child-initiated request
    (`ask_client`, which still earns today's D4 `-32601`) and asserts the
    table is EMPTY afterwards — a positive check on state, not an
    absence-of-symptoms observation.
    """
    url, pool = gateway_with_pool
    for body, headers in (
        (
            _modern_body(
                "tools/call",
                params={"name": "echo_tool", "arguments": {}},
                meta=_meta(),
            ),
            _modern_headers("tools/call", name="echo_tool"),
        ),
        (_modern_body("tools/list", meta=_meta()), _modern_headers()),
        (_modern_body("ask_client", meta=_meta()), _modern_headers("ask_client")),
    ):
        _post(url, body, headers)
    backend, _, entry = pool.get_or_create(None)
    try:
        assert backend._mrtr_pending == {}
        assert backend.mrtr_has_pending() is False
    finally:
        pool.release(entry)


class TestMrtrDispatchClaim:
    """The invariant is a CLAIM, not a read of the parked table.

    #389's review found the difference the hard way: a round only enters
    `_mrtr_pending` once the child has actually asked something, so
    between "an eligible request was forwarded" and that moment the table
    says nothing at all. Two handler threads for one principal could both
    read it empty and both forward — the exact two-eligible-calls-on-one-
    child state the invariant exists to forbid.
    """

    def _backend(self):
        return server.BackendProcess([*_BACKEND], modern_owned=True)

    def test_only_one_of_many_racing_claims_wins(self):
        """Barrier-synchronized, because a check-then-act hole only shows
        up under real simultaneity — the same idiom the pool tests use,
        and the same lesson #382's review taught for the listen cap.

        Revert-check: split `mrtr_begin_dispatch` into a read followed by
        a separate set and this reports several winners.
        """
        backend = self._backend()
        try:
            wins: list[bool] = []
            lock = threading.Lock()
            barrier = threading.Barrier(16)

            def _race():
                barrier.wait()
                got = backend.mrtr_begin_dispatch()
                with lock:
                    wins.append(got)

            threads = [threading.Thread(target=_race) for _ in range(16)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
            assert sum(wins) == 1, wins
        finally:
            backend.shutdown()

    def test_the_claim_is_released_and_reusable(self):
        backend = self._backend()
        try:
            assert backend.mrtr_begin_dispatch() is True
            assert backend.mrtr_begin_dispatch() is False
            backend.mrtr_end_dispatch()
            assert backend.mrtr_begin_dispatch() is True
        finally:
            backend.shutdown()

    def test_a_parked_round_keeps_excluding_after_the_claim_drops(self):
        """The handover, and why `mrtr_begin_dispatch` checks BOTH states.

        A dispatch that parks a round returns — dropping its claim — while
        the round is still outstanding. If the claim were the only gate,
        that release would reopen the child to a second eligible call
        with a prompt still pending. `_mrtr_pending` carries the
        exclusion onward, so no window opens between the two.
        """
        backend = self._backend()
        try:
            assert backend.mrtr_begin_dispatch() is True
            txn = backend.mrtr_round_open(
                "u1",
                method="tools/call",
                child_request_id="c1",
                declared_caps={},
                principal="alice",
            )
            backend.mrtr_end_dispatch()  # the dispatch returned
            assert backend.mrtr_begin_dispatch() is False, (
                "the parked round stopped excluding once the claim dropped"
            )
            backend.mrtr_round_consume(txn)
            assert backend.mrtr_begin_dispatch() is True
        finally:
            backend.shutdown()

    def test_two_concurrent_eligible_calls_race_over_http(self, gateway_with_pool):
        """The finding's own scenario, end to end.

        Two handler threads, one principal, one child, both dispatching
        an eligible method with genuine overlap — held open by blocking
        the child's reply until both are inside. Exactly one must be
        served; the other gets the busy error.

        Overlap is FORCED rather than hoped for: without the gate the two
        would simply both succeed, which is the bug, so a test that
        merely fired two requests and happened not to overlap would pass
        against the broken code.
        """
        url, pool = gateway_with_pool
        release = threading.Event()
        backend, _, entry = pool.get_or_create(None)
        pool.release(entry)
        original = backend.send_request

        def _blocking(line, req_id, timeout):
            release.wait(timeout=15)
            return original(line, req_id, timeout)

        backend.send_request = _blocking  # type: ignore[method-assign]
        statuses: list[int] = []
        lock = threading.Lock()
        started = threading.Barrier(2)

        def _call():
            started.wait(timeout=10)
            resp = _post(
                url,
                _modern_body(
                    "tools/call",
                    params={"name": "echo_tool", "arguments": {}},
                    meta=_meta(),
                ),
                _modern_headers("tools/call", name="echo_tool"),
            )
            with lock:
                statuses.append(resp.status_code)

        threads = [threading.Thread(target=_call, daemon=True) for _ in range(2)]
        for t in threads:
            t.start()
        # Let the loser reach its 503 before unblocking the winner, so the
        # two genuinely overlap rather than serialising.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with lock:
                if statuses:
                    break
            time.sleep(0.02)
        release.set()
        for t in threads:
            t.join(timeout=20)

        assert sorted(statuses) == [200, 503], statuses


# --- reverse MRTR: translation (#375 PR 2) -------------------------------


class TestMrtrTranslation:
    """The inversion of relay's PR C, in both directions."""

    def test_a_child_request_becomes_a_bare_input_entry(self):
        """Relay MINTS an envelope around a bare object; serve STRIPS one
        back off, because `inputRequests` values "MUST be one of
        ElicitRequest, CreateMessageRequest, or ListRootsRequest" — bare
        request objects, not JSON-RPC messages."""
        cap, entry = server._mrtr_request_to_input_entry(
            {
                "jsonrpc": "2.0",
                "id": "child-1",
                "method": "sampling/createMessage",
                "params": {"messages": [], "maxTokens": 10},
            }
        )
        assert cap == "sampling"
        assert entry == {
            "method": "sampling/createMessage",
            "params": {"messages": [], "maxTokens": 10},
        }
        # The envelope is gone: no id, no jsonrpc.
        assert "id" not in entry and "jsonrpc" not in entry

    def test_roots_list_carries_no_params(self):
        cap, entry = server._mrtr_request_to_input_entry(
            {"jsonrpc": "2.0", "id": 1, "method": "roots/list"}
        )
        assert cap == "roots"
        assert entry == {"method": "roots/list"}

    def test_every_bridgeable_method_maps_to_its_capability(self):
        assert server._MRTR_REQUEST_CAPABILITY == {
            "elicitation/create": "elicitation",
            "sampling/createMessage": "sampling",
            "roots/list": "roots",
        }

    def test_an_unbridgeable_method_is_refused_with_a_reason(self):
        for method in ("tools/list", "notifications/message", None, ""):
            cap, reason = server._mrtr_request_to_input_entry({"method": method})
            assert cap is None, method
            assert reason, method

    def test_params_pass_through_verbatim(self):
        """Inventing a lossy down-translation would be worse than passing
        what the child actually said — every MCP request object is
        open/extensible."""
        params = {"messages": [{"role": "user"}], "unknownFuture": {"x": 1}}
        _, entry = server._mrtr_request_to_input_entry(
            {"method": "sampling/createMessage", "params": params}
        )
        assert entry["params"] == params

    def test_no_reject_arms_for_shapes_a_legacy_child_cannot_emit(self):
        """Narrower than relay ON PURPOSE (#375 §2, §4 Q6).

        Relay must refuse `mode: "url"` elicitation and tool-augmented
        sampling because a modern SERVER can express them and a legacy
        client cannot consume them. Here the CHILD is the legacy side and
        structurally cannot emit either — both are 2025-11-25+ additions.
        So they pass through as ordinary params rather than being
        rejected, and this pins that as a DECISION rather than letting a
        reviewer read it as a missed case.
        """
        cap, entry = server._mrtr_request_to_input_entry(
            {"method": "elicitation/create", "params": {"mode": "url", "url": "x"}}
        )
        assert cap == "elicitation"
        assert entry["params"]["mode"] == "url"

    def test_a_malformed_params_is_refused(self):
        cap, reason = server._mrtr_request_to_input_entry(
            {"method": "elicitation/create", "params": "nope"}
        )
        assert cap is None and reason

    def test_an_input_response_becomes_the_reply_the_child_awaits(self):
        line, why = server._mrtr_input_response_to_reply(
            {"result": {"action": "accept", "content": {"name": "x"}}}, "child-1"
        )
        assert why == ""
        assert json.loads(line) == {
            "jsonrpc": "2.0",
            "id": "child-1",
            "result": {"action": "accept", "content": {"name": "x"}},
        }

    def test_a_bare_result_object_is_accepted_too(self):
        """The client's `InputResponse` IS the result; a caller that
        hands the result directly must work the same way."""
        line, why = server._mrtr_input_response_to_reply({"action": "decline"}, 7)
        assert why == ""
        assert json.loads(line)["result"] == {"action": "decline"}

    def test_a_client_error_is_forwarded_as_a_jsonrpc_error(self):
        """A user declining is a legitimate OUTCOME, not a bridge
        failure — the child must learn what happened rather than see the
        gateway swallow it."""
        line, why = server._mrtr_input_response_to_reply(
            {"error": {"code": -32001, "message": "user declined"}}, "child-1"
        )
        assert why == ""
        assert json.loads(line)["error"]["code"] == -32001

    def test_a_non_dict_error_value_is_malformed_not_a_success(self):
        """#390 Copilot review — the nastiest shape in this function.

        A non-dict `error` used to SKIP the error branch and fall into
        the bare-result path, where `.get("result", response)` fell back
        to the whole object. So `{"error": "x"}` came out as a SUCCESS
        carrying `result: {"error": "x"}` — a child that asked a question
        was told its request succeeded and handed the error as the
        answer. Silent, and exactly backwards.

        Revert-check: restore the `and isinstance(...)` fall-through and
        this returns a success line instead of a refusal.
        """
        for bad_error in ("x", 7, None, [], ["a"]):
            line, why = server._mrtr_input_response_to_reply({"error": bad_error}, "c1")
            assert line is None, (bad_error, line)
            assert why, bad_error

    def test_the_error_key_decides_the_shape_with_no_fall_through(self):
        """The three legal shapes still resolve as they did — the fix
        narrows one hole without moving the others."""
        # A real error is forwarded as an error.
        line, _ = server._mrtr_input_response_to_reply(
            {"error": {"code": -1, "message": "no"}}, "c1"
        )
        assert json.loads(line)["error"]["code"] == -1
        # An explicit result is unwrapped.
        line, _ = server._mrtr_input_response_to_reply({"result": {"ok": 1}}, "c1")
        assert json.loads(line)["result"] == {"ok": 1}
        # And a bare result object — no `error`, no `result` — is still
        # accepted as the result itself.
        line, _ = server._mrtr_input_response_to_reply({"action": "decline"}, "c1")
        assert json.loads(line)["result"] == {"action": "decline"}

    def test_a_malformed_input_response_is_refused(self):
        for bad in (None, 7, "x", {"result": "not-an-object"}):
            line, why = server._mrtr_input_response_to_reply(bad, "c1")
            assert line is None, bad
            assert why, bad


class TestMrtrRoundOneMinting:
    """A child's mid-call request becomes an `InputRequiredResult`.

    The unit `gateway` fixture is NO-AUTH, which is exactly why these
    tests drive `_mrtr_try_bridge` against a `BackendProcess` directly:
    under no auth the OAuth-only gate publishes no bridging context at
    all, so the HTTP path cannot reach this code — and that fact is
    itself pinned, below.
    """

    def _backend(self):
        return server.BackendProcess([*_BACKEND], modern_owned=True)

    def test_no_context_means_no_bridge(self):
        """The D4 fallthrough stays the default outcome: unbridgeable is
        the answer whenever anything at all is missing."""
        backend = self._backend()
        try:
            assert backend._mrtr_try_bridge({"id": 1, "method": "roots/list"}) is False
        finally:
            backend.shutdown()

    def test_a_bridged_request_wakes_the_parked_handler(self):
        """Round-1 minting needs NO new response path: the handler is
        already blocked in `send_request` on this slot, so filling it and
        setting the event delivers the result through the existing
        stamp/send machinery.

        Asserted on the line the handler would receive — wire evidence,
        not "no hang observed".
        """
        backend = self._backend()
        try:
            got: list[str] = []

            def _wait():
                line = backend.send_request(
                    json.dumps({"jsonrpc": "2.0", "id": "U1", "method": "noreply"}),
                    "U1",
                    10.0,
                )
                got.append(line)

            assert backend.mrtr_begin_dispatch(
                {
                    "upstream_id": "U1",
                    "declared_caps": {"sampling": {}},
                    "principal": "alice",
                    "round": 1,
                }
            )
            waiter = threading.Thread(target=_wait, daemon=True)
            waiter.start()
            deadline = time.monotonic() + 10
            while not backend.has_pending and time.monotonic() < deadline:
                time.sleep(0.01)
            assert backend._mrtr_try_bridge(
                {
                    "jsonrpc": "2.0",
                    "id": "child-9",
                    "method": "sampling/createMessage",
                    "params": {"messages": []},
                }
            )
            waiter.join(timeout=10)
            assert got and got[0] is not None
            result = json.loads(got[0])["result"]
            assert result["resultType"] == "input_required"
            # The gateway INVENTS the key from the child's own id.
            assert list(result["inputRequests"]) == ["child-9"]
            assert result["inputRequests"]["child-9"]["method"] == (
                "sampling/createMessage"
            )
            # And the pointer is a real, verifiable one.
            payload, why = server._mrtr_decode_pointer(result["requestState"], "alice")
            assert why == "" and payload["round"] == 1
            # The round is parked, keyed to the child's own request id.
            found = backend.mrtr_round_for_txn(payload["txn_id"])
            assert found is not None and found[1]["child_request_id"] == "child-9"
        finally:
            backend.shutdown()

    def test_an_undeclared_capability_aborts_with_32021(self):
        """O11: "the server MUST return a
        `MissingRequiredClientCapabilityError` (-32021) whose
        `data.requiredCapabilities` lists the missing capabilities."

        No relay precedent to copy — relay can never emit this, only
        servers can — so copying its generic abort would be
        non-conformant. And NO round is opened: there is nothing to retry
        into.
        """
        backend = self._backend()
        try:
            got: list[str] = []

            def _wait():
                got.append(
                    backend.send_request(
                        json.dumps({"jsonrpc": "2.0", "id": "U1", "method": "noreply"}),
                        "U1",
                        10.0,
                    )
                )

            assert backend.mrtr_begin_dispatch(
                {
                    "upstream_id": "U1",
                    "declared_caps": {"elicitation": {}},  # no sampling
                    "principal": "alice",
                    "round": 1,
                }
            )
            waiter = threading.Thread(target=_wait, daemon=True)
            waiter.start()
            deadline = time.monotonic() + 10
            while not backend.has_pending and time.monotonic() < deadline:
                time.sleep(0.01)
            assert backend._mrtr_try_bridge(
                {"jsonrpc": "2.0", "id": "c1", "method": "sampling/createMessage"}
            )
            waiter.join(timeout=10)
            error = json.loads(got[0])["error"]
            assert error["code"] == -32021
            assert error["data"]["requiredCapabilities"] == ["sampling"]
            assert not backend.mrtr_has_pending(), "a round was opened anyway"
        finally:
            backend.shutdown()

    def test_a_vanished_handler_falls_through_rather_than_parking(self):
        """If the handler timed out between the context read and the
        answer, the round must NOT be left parked for a retry that can
        never be correlated — and the caller must still answer the child,
        or it stays blocked forever."""
        backend = self._backend()
        try:
            assert backend.mrtr_begin_dispatch(
                {
                    "upstream_id": "U-gone",
                    "declared_caps": {"roots": {}},
                    "principal": "alice",
                    "round": 1,
                }
            )
            # No waiter was ever registered for U-gone.
            assert (
                backend._mrtr_try_bridge(
                    {"jsonrpc": "2.0", "id": "c1", "method": "roots/list"}
                )
                is False
            )
            assert backend.mrtr_has_pending() is False
        finally:
            backend.shutdown()


def test_a_no_auth_gateway_publishes_no_bridging_context(gateway_with_pool):
    """§4 Q1's boundary, end to end, and the reason it is safe to remove
    the D4 valve: a no-auth deployment gets NO bridging context, so a
    child that asks still meets the `-32601`.

    Asserted on the child's actual answer — the fake backend's
    `ask_client` really does raise `elicitation/create` mid-call — rather
    than on the absence of a bridge.
    """
    url, pool = gateway_with_pool
    resp = _post(
        url, _modern_body("ask_client", meta=_meta()), _modern_headers("ask_client")
    )
    assert resp.status_code == 200, resp.text
    # The child got its D4 reject and completed normally.
    assert resp.json()["result"]["asked"] is True
    backend, _, entry = pool.get_or_create(None)
    try:
        assert backend.mrtr_context() is None
        assert backend.mrtr_has_pending() is False
    finally:
        pool.release(entry)


class TestMrtrRetryFailurePaths:
    """After the round is consumed, the child is owed a reply on EVERY exit.

    #390's review found two paths that answered only the client, leaving
    the subprocess blocked forever — the round was already gone from the
    table, so nothing else could ever reply to it. Every test here asserts
    WIRE EVIDENCE that the child got an error for its own id, not merely
    that the client got one.
    """

    def _park(self, backend, *, declared=None, round_no=1):
        """Park a round the way a real mint would, and return its pointer."""
        txn = backend.mrtr_round_open(
            "U1",
            method="tools/call",
            child_request_id="child-7",
            declared_caps=declared if declared is not None else {"sampling": {}},
            # The `gateway_with_pool` fixture is NO-AUTH, so the live
            # principal is None. The pointer's principal binding compares
            # against whatever the CURRENT request resolves to, so a round
            # parked under any other value would be rejected before these
            # failure paths could be reached at all — which is itself the
            # binding working, just not what these tests are about.
            principal=None,
            round_no=round_no,
        )
        return server._mrtr_encode_pointer(txn, None, round_no)

    def _retry(self, url, state, responses="default", meta=None):
        params = {"_meta": meta if meta is not None else _meta()}
        params["requestState"] = state
        if responses != "omit":
            params["inputResponses"] = (
                {"child-7": {"result": {"ok": True}}}
                if responses == "default"
                else responses
            )
        return _post(
            url,
            {
                "jsonrpc": "2.0",
                "id": "retry-1",
                "method": "tools/call",
                "params": params,
            },
            _modern_headers("tools/call"),
        )

    def test_a_stale_pointer_leaves_the_round_and_the_child_alone(
        self, gateway_with_pool
    ):
        """Updated when validation moved BEFORE the consume (#390).

        This used to assert the opposite — that a stale pointer unblocks
        the child — and that was right while the round was consumed
        first. Now the stale check runs on a PEEK, so the round survives
        and may still be redeemed by its real owner: unblocking the child
        here would destroy a live transaction on behalf of an impostor.

        Finding B's rule is unchanged and still holds — every path AFTER
        the consume owes the child a reply. This path simply is no longer
        one of them.
        """
        url, pool = gateway_with_pool
        backend, _, entry = pool.get_or_create(None)
        pool.release(entry)
        state = self._park(backend, round_no=1)
        # Corrupt the parked entry's round so the pointer reads stale.
        with backend._mrtr_lock:
            next(iter(backend._mrtr_pending.values()))["round"] = 9
        sent: list[str] = []
        backend.send_oneway = lambda line: sent.append(line) or True  # type: ignore
        resp = self._retry(url, state)
        assert resp.status_code == 400, resp.text
        assert "stale" in resp.json()["error"]["message"]
        assert sent == [], "a stale pointer unblocked a child it does not own"
        assert backend.mrtr_has_pending(), "a stale pointer destroyed a live round"

    def test_missing_input_responses_unblocks_the_child_before_erroring(
        self, gateway_with_pool
    ):
        """Finding B, half two."""
        url, pool = gateway_with_pool
        backend, _, entry = pool.get_or_create(None)
        pool.release(entry)
        state = self._park(backend)
        sent: list[str] = []
        backend.send_oneway = lambda line: sent.append(line) or True  # type: ignore
        resp = self._retry(url, state, responses="omit")
        assert resp.status_code == 400, resp.text
        assert "inputResponses" in resp.json()["error"]["message"]
        assert sent and json.loads(sent[0])["id"] == "child-7"

    def test_a_lost_claim_aborts_instead_of_resuming_the_child(self, gateway_with_pool):
        """Finding A, the blocking one.

        Consuming the round leaves the child momentarily unclaimed, and a
        brand-new eligible request can win the claim in that window.
        Resuming anyway would put the child back to work while someone
        else holds the dispatch claim — and a second question would
        bridge into the wrong context.

        The race is FORCED rather than hoped for: the claim is taken by a
        stand-in before the retry runs, which is exactly the state the
        window produces.

        Revert-check: call `resume_request` regardless of `claimed` and
        this returns 200 with the child resumed.
        """
        url, pool = gateway_with_pool
        backend, _, entry = pool.get_or_create(None)
        pool.release(entry)
        state = self._park(backend)
        resumed: list[str] = []
        backend.resume_request = (  # type: ignore[method-assign]
            lambda reply, rid, timeout: (resumed.append(reply), (None, True))[1]
        )
        sent: list[str] = []
        backend.send_oneway = lambda line: sent.append(line) or True  # type: ignore

        # A concurrent claimant wins the window.
        def _steal():
            with backend._mrtr_lock:
                if not backend._mrtr_pending:
                    backend._mrtr_inflight = True

        original_consume = backend.mrtr_round_consume

        def _consume_then_steal(txn):
            out = original_consume(txn)
            _steal()
            return out

        backend.mrtr_round_consume = _consume_then_steal  # type: ignore
        resp = self._retry(url, state)

        assert resp.status_code == 503, resp.text
        assert "concurrent" in resp.json()["error"]["message"]
        assert resumed == [], "the child was resumed despite a lost claim"
        assert sent and json.loads(sent[0])["id"] == "child-7"

    def test_the_next_round_uses_the_retrys_own_capabilities(self, gateway_with_pool):
        """Finding C. O5 makes `clientCapabilities` PER REQUEST, and the
        retry is a fresh, separately-validated one — so a second
        `input_required` mint must gate against what THIS request
        declared, not what the original did.

        Revert-check: pass `entry["declared_caps"]` and the context shows
        the original's capabilities instead.
        """
        url, pool = gateway_with_pool
        backend, _, entry = pool.get_or_create(None)
        pool.release(entry)
        # Original round declared sampling only.
        state = self._park(backend, declared={"sampling": {}})
        seen: list[dict] = []

        def _capture(reply, rid, timeout):
            ctx = backend.mrtr_context()
            seen.append(dict(ctx) if ctx else {})
            return (
                json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"ok": True}}),
                True,
            )

        backend.resume_request = _capture  # type: ignore[method-assign]
        # The RETRY declares elicitation instead.
        retry_meta = {**_meta(), META_CAPS: {"elicitation": {}}}
        resp = self._retry(url, state, meta=retry_meta)
        assert resp.status_code == 200, resp.text
        assert seen and seen[0]["declared_caps"] == {"elicitation": {}}, seen
        assert seen[0]["round"] == 2
        # Finding 4: a RESUMED response carries the child's `serverInfo`
        # like every other modern result. Omitting it made this the one
        # response missing the `_meta` the spec says servers SHOULD put
        # on every result — invisible until someone compared two
        # responses to the same tool.
        #
        # Revert-check: pass `server_info=None` and this key disappears.
        meta = resp.json()["result"]["_meta"]
        assert meta["io.modelcontextprotocol/serverInfo"]["name"] == "fake", meta


class TestMrtrAbandonedAndCapped:
    """The never-hang invariant, at the two ends #390's review found open."""

    def test_an_abandoned_round_is_swept_and_the_child_unblocked(self):
        """Finding 1. A client is EXPLICITLY licensed not to come back
        ("Servers MUST NOT assume that clients will fulfill the
        inputRequests or retry"), so an unswept round left the child
        blocked forever AND wedged the principal's pool slot, since
        `mrtr_begin_dispatch` refuses while anything is parked.

        Wire evidence: the child receives an error under its OWN request
        id. Revert-check: remove the `_sweep_abandoned_rounds()` call and
        nothing is written and the slot stays wedged.
        """
        clock = [1000.0]
        pool = server.ModernBackendPool(_BACKEND, idle_ttl=0.0, now=lambda: clock[0])
        try:
            backend, _, entry = pool.get_or_create("alice")
            pool.release(entry)
            sent: list[str] = []
            backend.send_oneway = lambda line: sent.append(line) or True  # type: ignore
            backend.mrtr_round_open(
                "U1",
                method="tools/call",
                child_request_id="child-42",
                declared_caps={},
                principal="alice",
                now=time.monotonic(),
            )
            assert backend.mrtr_begin_dispatch() is False, "slot should be wedged"
            # Before the deadline: nothing swept.
            pool.reap_idle()
            assert sent == []
            # Past it: the child is told, and the slot frees up.
            with backend._mrtr_lock:
                for e in backend._mrtr_pending.values():
                    e["park_deadline"] = time.monotonic() - 1
            pool.reap_idle()
            assert sent, "the child was never unblocked"
            assert json.loads(sent[0])["id"] == "child-42"
            assert "error" in json.loads(sent[0])
            assert backend.mrtr_begin_dispatch() is True, "the slot stayed wedged"
        finally:
            pool.shutdown_all()

    def test_the_reaper_thread_starts_for_the_bridge_without_any_idle_ttl(
        self, monkeypatch
    ):
        """#390 R3F1 — the layer above the sweep.

        Placing the sweep outside `reap_idle`'s TTL check was right, and
        insufficient: `start_reaper` gated the whole THREAD on the TTL,
        so in the default deployment nothing ever called `reap_idle` at
        all. That is finding 1 again, one layer up — and the test that
        was here before could not see it, because it called
        `reap_idle()` directly rather than letting the thread do it.

        This drives the real thread end to end with NO idle TTL, and
        asserts wire evidence that the child was unblocked.

        Revert-check: restore the `self._idle_ttl <= 0` gate and no
        thread starts, so the child is never unblocked and this times
        out.
        """
        monkeypatch.setenv("MCP_STDIO_MRTR_REVERSE_ENABLE", "1")
        monkeypatch.setattr(server, "_MRTR_PARK_TIMEOUT_SECS", 4.0)
        pool = server.ModernBackendPool(_BACKEND, idle_ttl=0.0)
        try:
            backend, _, entry = pool.get_or_create("alice")
            pool.release(entry)
            sent: list[str] = []
            backend.send_oneway = lambda line: sent.append(line) or True  # type: ignore
            backend.mrtr_round_open(
                "U1",
                method="tools/call",
                child_request_id="c-abandoned",
                declared_caps={},
                principal="alice",
                now=time.monotonic() - 99,  # already past its deadline
            )
            pool.start_reaper()
            assert pool._reaper is not None, "no reaper thread started"
            deadline = time.monotonic() + 15
            while not sent and time.monotonic() < deadline:
                time.sleep(0.05)
            assert sent, "the reaper never swept the abandoned round"
            assert json.loads(sent[0])["id"] == "c-abandoned"
            # Idle eviction stays OFF: a bridge-only reaper evicts nothing.
            assert pool.count() == 1, "an idle child was evicted with ttl=0"
        finally:
            pool.stop_reaper()
            pool.shutdown_all()

    def test_the_sweep_itself_ignores_the_idle_ttl(self):
        """The sweep's own placement, independent of who calls it: the
        park deadline is the ROUND's, not the pool's."""
        pool = server.ModernBackendPool(_BACKEND, idle_ttl=0.0)
        try:
            backend, _, entry = pool.get_or_create("alice")
            pool.release(entry)
            sent: list[str] = []
            backend.send_oneway = lambda line: sent.append(line) or True  # type: ignore
            backend.mrtr_round_open(
                "U1",
                method="tools/call",
                child_request_id="c1",
                declared_caps={},
                principal="alice",
                now=time.monotonic() - server._MRTR_PARK_TIMEOUT_SECS - 1,
            )
            pool.reap_idle()
            assert sent and json.loads(sent[0])["id"] == "c1"
        finally:
            pool.shutdown_all()

    def test_a_round_past_the_cap_is_refused_at_mint_time(self):
        """Finding 2. `_mrtr_decode_pointer` refuses a pointer past the
        cap, so minting one would hand the client a `requestState` it can
        NEVER redeem — parked until the park timeout, and before finding
        1 was fixed, forever.

        The child is told so it stops waiting; its own call then fails
        through the ordinary path rather than the gateway inventing a
        competing error for a call the child can still answer.

        Revert-check: drop the cap check and a round IS parked with an
        unredeemable pointer.
        """
        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        try:
            sent: list[str] = []
            backend._write = lambda line: sent.append(line) or True  # type: ignore
            assert backend.mrtr_begin_dispatch(
                {
                    "upstream_id": "U1",
                    "declared_caps": {"roots": {}},
                    "principal": "alice",
                    "round": server._MRTR_MAX_ROUNDS + 1,
                }
            )
            assert backend._mrtr_try_bridge(
                {"jsonrpc": "2.0", "id": "c1", "method": "roots/list"}
            )
            assert sent and json.loads(sent[0])["id"] == "c1"
            assert "error" in json.loads(sent[0])
            assert backend.mrtr_has_pending() is False, "an unredeemable round parked"
        finally:
            backend.shutdown()

    def test_a_second_round_never_overwrites_a_parked_one(self):
        """Finding 3. Overwriting would ORPHAN the first round: its txn id
        still rides a client-held `requestState`, and the entry that
        pointer names would silently become a different round.

        Steady state cannot reach this — a parked round means the handler
        already returned and cleared the context — but a child that
        ignores its own blocking read can, and guessing costs an
        unredeemable pointer.
        """
        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        try:
            first = backend.mrtr_round_open(
                "U1",
                method="tools/call",
                child_request_id="c1",
                declared_caps={},
                principal="alice",
            )
            second = backend.mrtr_round_open(
                "U1",
                method="tools/call",
                child_request_id="c2",
                declared_caps={},
                principal="alice",
            )
            assert second == "", "a second round overwrote the first"
            found = backend.mrtr_round_for_txn(first)
            assert found is not None and found[1]["child_request_id"] == "c1"
        finally:
            backend.shutdown()

    def test_an_undelivered_resume_still_answers_the_child(self):
        """Finding 5, the one sub-case that was real: `resume_request`
        returns None from several places, and only ONE of them means the
        child was never told. A timeout after a successful write means it
        WAS told, so re-answering would put a second reply on its stream.
        """
        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        try:
            # Occupy the slot so `resume_request` takes its
            # ambiguous-correlation early return.
            with backend._lock:
                backend._pending["U1"] = {
                    "event": threading.Event(),
                    "line": None,
                    "request_line": "",
                    "waiters": 1,
                }
            line, delivered = backend.resume_request("{}", "U1", 1.0)
            assert line is None and delivered is False
            # A closed child: unreachable, so nothing is owed.
            backend.shutdown()
            line, delivered = backend.resume_request("{}", "U2", 1.0)
            assert line is None and delivered is True
        finally:
            backend.shutdown()


class TestMrtrHostileChildAndFlagGate:
    """#390 Copilot round 3: a DoS and a switch that did not switch."""

    def test_an_unhashable_method_does_not_kill_the_reader_thread(self):
        """A truthy-but-unhashable `method` used to raise
        `TypeError: unhashable type` inside the child's READER thread,
        whose `try/except` sits OUTSIDE its `while` loop — so it ended
        the loop, hit `_fail_all("backend process exited")`, and failed
        every in-flight request on a subprocess that was still perfectly
        alive. One malformed field, all traffic to that child gone.

        WIRE EVIDENCE: an unrelated request still round-trips afterwards,
        which is the thing the crash destroyed. Asserting only that the
        translate call returns a reason would miss the actual damage.

        Revert-check: drop the `isinstance(method, str)` guard and this
        raises out of `_route`, taking the reader thread with it.
        """
        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        try:
            for hostile in ({"a": 1}, ["x"], {"nested": ["deep"]}):
                cap, why = server._mrtr_request_to_input_entry({"method": hostile})
                assert cap is None and why, hostile
                # Straight through the real reader-thread path, too.
                backend._route(
                    json.dumps({"jsonrpc": "2.0", "id": 1, "method": hostile})
                )
            # The child is still fully usable — the reader survived.
            line = backend.send_request(
                json.dumps({"jsonrpc": "2.0", "id": "still-alive", "method": "echo"}),
                "still-alive",
                10.0,
            )
            assert line is not None, "the reader thread died"
            assert json.loads(line)["id"] == "still-alive"
            assert backend.closed is False
        finally:
            backend.shutdown()

    def test_the_flag_gates_bridging_not_only_the_advertisement(
        self, gateway_with_pool, monkeypatch
    ):
        """The switch has to switch.

        `_modern_child_capabilities()` was consulted only where serve
        ADVERTISES to a child, so turning the flag off withdrew the offer
        while leaving the bridge live — a child that ignored the
        advertisement and asked anyway was still bridged, provided the
        caller was OAuth-authenticated. The flag exists so an operator
        can withdraw this "without a code rollback", and a switch that
        only changes what serve SAYS does not do that.

        Revert-check: drop the `and _modern_child_capabilities()` term
        and a round is minted with the flag off.
        """
        url, pool = gateway_with_pool
        # Stand in for an OAuth principal, so the OTHER gate is satisfied
        # and this test is actually about the flag. Without this the
        # unit fixture is no-auth and would pass for the wrong reason.
        monkeypatch.setattr(server, "_mrtr_principal_is_eligible", lambda p: True)
        seen: list = []
        original = server.BackendProcess.mrtr_begin_dispatch

        def _record(self, context=None):
            seen.append(context)
            return original(self, context)

        monkeypatch.setattr(server.BackendProcess, "mrtr_begin_dispatch", _record)

        monkeypatch.delenv("MCP_STDIO_MRTR_REVERSE_ENABLE", raising=False)
        assert server._modern_child_capabilities() == {}
        _post(
            url,
            _modern_body(
                "tools/call",
                params={"name": "echo_tool", "arguments": {}},
                meta=_meta(),
            ),
            _modern_headers("tools/call", name="echo_tool"),
        )
        assert seen and seen[-1] is None, (
            "the flag was off but a bridging context was still built"
        )

        # Flag on: the same request DOES publish a context.
        monkeypatch.setenv("MCP_STDIO_MRTR_REVERSE_ENABLE", "1")
        _post(
            url,
            _modern_body(
                "tools/call",
                params={"name": "echo_tool", "arguments": {}},
                meta=_meta(),
            ),
            _modern_headers("tools/call", name="echo_tool"),
        )
        assert seen[-1] is not None, "the flag was on but nothing bridged"

    def test_flipping_the_flag_off_stops_bridging_on_a_running_child(self, monkeypatch):
        """Read live, not captured at spawn: withdrawing must take effect
        on children already running, which is what an operator holding an
        incident actually needs."""
        monkeypatch.setenv("MCP_STDIO_MRTR_REVERSE_ENABLE", "1")
        assert server._modern_child_capabilities() != {}
        monkeypatch.delenv("MCP_STDIO_MRTR_REVERSE_ENABLE", raising=False)
        assert server._modern_child_capabilities() == {}


class TestMrtrRetryMethodGate:
    """A `requestState` is only a retry OF THE METHOD THAT OPENED THE ROUND."""

    def test_a_pointer_on_a_non_eligible_method_is_not_a_retry(self, gateway_with_pool):
        """#390 Copilot review. `params.requestState` alone used to be
        enough to enter the retry path, whatever the method was.

        The damage compounds: single-use consumption destroys the round,
        so the REAL retry finds nothing left and the original
        `tools/call` can never be answered — while the response carries
        the wrong method into `_stamp_modern_result`, applying
        `resources/list` cache semantics to a `tools/call` result.

        WIRE EVIDENCE that it fell through to ordinary dispatch: the
        child answers `resources/list` itself (`-32601`, since the fake
        child does not implement it) rather than the gateway synthesizing
        a resumed result — and crucially the round is STILL PARKED
        afterwards, which is what lets a correct retry succeed.

        Revert-check: drop `and method in _MRTR_ELIGIBLE_METHODS` and the
        round is consumed by a request that never opened it.
        """
        url, pool = gateway_with_pool
        backend, _, entry = pool.get_or_create(None)
        pool.release(entry)
        txn = backend.mrtr_round_open(
            "U1",
            method="tools/call",
            child_request_id="child-7",
            declared_caps={},
            principal=None,
        )
        state = server._mrtr_encode_pointer(txn, None, 1)
        resp = _post(
            url,
            {
                "jsonrpc": "2.0",
                "id": "stray-1",
                "method": "resources/list",
                "params": {"_meta": _meta(), "requestState": state},
            },
            _modern_headers("resources/list"),
        )
        # Ordinary dispatch: the CHILD answered, not the bridge.
        assert resp.status_code == 404, resp.text
        assert resp.json()["error"]["code"] == -32601
        # And the round survived for the request that actually owns it.
        assert backend.mrtr_round_for_txn(txn) is not None, (
            "a stray method consumed a round it never opened"
        )

    def test_an_eligible_method_still_takes_the_retry_path(self, gateway_with_pool):
        """The gate must not break the three methods that CAN open a
        round — otherwise the fix trades one bug for a worse one."""
        url, pool = gateway_with_pool
        backend, _, entry = pool.get_or_create(None)
        pool.release(entry)
        for method in sorted(server._MRTR_ELIGIBLE_METHODS):
            txn = backend.mrtr_round_open(
                "U1",
                method=method,
                child_request_id="c1",
                declared_caps={},
                principal=None,
            )
            state = server._mrtr_encode_pointer(txn, None, 1)
            backend.send_oneway = lambda line: True  # type: ignore[method-assign]
            resp = _post(
                url,
                {
                    "jsonrpc": "2.0",
                    "id": f"retry-{method}",
                    "method": method,
                    "params": {"_meta": _meta(), "requestState": state},
                },
                _modern_headers(method),
            )
            # Reached `_serve_mrtr_retry`: it rejects for a MISSING
            # `inputResponses`, which only that path can produce.
            assert resp.status_code == 400, (method, resp.text)
            assert "inputResponses" in resp.json()["error"]["message"], method
            # And it consumed the round, as a real retry does.
            assert backend.mrtr_round_for_txn(txn) is None, method


class TestMrtrRetryMethodExactMatch:
    """A pointer redeems the round it opened — not merely *a* round."""

    def test_a_pointer_from_one_eligible_method_cannot_redeem_another(
        self, gateway_with_pool
    ):
        """#390 Copilot review, the follow-on to the eligibility gate.

        `method in _MRTR_ELIGIBLE_METHODS` proves a request COULD have
        opened a round. It does not prove it opened THIS one — so a
        pointer minted by `tools/call` could be redeemed by
        `resources/read`, both eligible, consuming a round belonging to a
        different in-flight call.

        WIRE EVIDENCE both ways: the mismatched retry is refused, AND the
        round is still parked afterwards, which is what lets its real
        owner finish.

        Revert-check: drop the `entry["method"] != msg.get("method")`
        term and the mismatched method consumes the round.
        """
        url, pool = gateway_with_pool
        backend, _, entry = pool.get_or_create(None)
        pool.release(entry)
        backend.send_oneway = lambda line: True  # type: ignore[method-assign]
        txn = backend.mrtr_round_open(
            "U1",
            method="tools/call",
            child_request_id="c1",
            declared_caps={},
            principal=None,
        )
        state = server._mrtr_encode_pointer(txn, None, 1)
        resp = _post(
            url,
            {
                "jsonrpc": "2.0",
                "id": "wrong-method",
                "method": "resources/read",
                "params": {
                    "_meta": _meta(),
                    "requestState": state,
                    "inputResponses": {"c1": {"result": {"ok": True}}},
                    "uri": "res://a",
                },
            },
            _modern_headers("resources/read", name="res://a"),
        )
        assert resp.status_code == 400, resp.text
        assert "stale" in resp.json()["error"]["message"], resp.text
        assert backend.mrtr_round_for_txn(txn) is not None, (
            "a different method consumed a round it did not open"
        )

    def test_a_round_records_the_upstream_method_not_the_childs_question(self):
        """The root cause, pinned directly.

        `mrtr_round_open` used to be handed `msg.get("method")` from
        inside `_mrtr_try_bridge`, where `msg` is the CHILD's question
        (`sampling/createMessage`) — a semantically different value from
        the client request the round belongs to (`tools/call`). The field
        exists to be compared against an incoming retry's method, so
        recording the wrong one made that comparison unwritable.

        Driven through the real bridge rather than by calling
        `mrtr_round_open` directly, because calling it directly is what
        made the existing tests agree with an intention production did
        not implement.
        """
        backend = server.BackendProcess([*_BACKEND], modern_owned=True)
        try:
            assert backend.mrtr_begin_dispatch(
                {
                    "upstream_id": "U1",
                    "declared_caps": {"sampling": {}},
                    "principal": "alice",
                    "method": "tools/call",
                    "round": 1,
                }
            )
            waiter = threading.Thread(
                target=lambda: backend.send_request(
                    json.dumps({"jsonrpc": "2.0", "id": "U1", "method": "noreply"}),
                    "U1",
                    10.0,
                ),
                daemon=True,
            )
            waiter.start()
            deadline = time.monotonic() + 10
            while not backend.has_pending and time.monotonic() < deadline:
                time.sleep(0.01)
            assert backend._mrtr_try_bridge(
                {
                    "jsonrpc": "2.0",
                    "id": "child-1",
                    "method": "sampling/createMessage",
                    "params": {"messages": []},
                }
            )
            waiter.join(timeout=10)
            parked = list(backend._mrtr_pending.values())
            assert parked and parked[0]["method"] == "tools/call", parked
        finally:
            backend.shutdown()


class TestBackendNonObjectResponse:
    """A backend answering valid-but-not-an-object JSON must not crash.

    `json.loads` raises on invalid JSON but NOT on `[1, 2, 3]` — that
    parses cleanly to a list, and the rekey that follows then raises
    `TypeError: list indices must be integers` OUTSIDE any handler.
    """

    def _park(self, backend):
        txn = backend.mrtr_round_open(
            "U1",
            method="tools/call",
            child_request_id="c1",
            declared_caps={},
            principal=None,
        )
        return server._mrtr_encode_pointer(txn, None, 1)

    def test_the_retry_path_survives_a_non_object_response(self, gateway_with_pool):
        """The reported site. Revert-check: drop the `isinstance(parsed,
        dict)` guard and this raises `TypeError` instead of answering."""
        url, pool = gateway_with_pool
        backend, _, entry = pool.get_or_create(None)
        pool.release(entry)
        backend.send_oneway = lambda line: True  # type: ignore[method-assign]
        for hostile in ("[1, 2, 3]", '"just a string"', "42", "null", "true"):
            state = self._park(backend)
            backend.resume_request = (  # type: ignore[method-assign]
                lambda reply, rid, timeout, _h=hostile: (_h, True)
            )
            resp = _post(
                url,
                {
                    "jsonrpc": "2.0",
                    "id": "retry-1",
                    "method": "tools/call",
                    "params": {
                        "_meta": _meta(),
                        "requestState": state,
                        "inputResponses": {"c1": {"result": {"ok": True}}},
                    },
                },
                _modern_headers("tools/call"),
            )
            assert resp.status_code == 502, (hostile, resp.text)
            assert "malformed response" in resp.json()["error"]["message"], hostile
        # The gateway is still serving afterwards — a traceback out of a
        # handler thread would have left this connection dead.
        assert (
            _post(
                url, _modern_body("tools/list", meta=_meta()), _modern_headers()
            ).status_code
            == 200
        )

    def test_the_ordinary_dispatch_path_survives_it_too(self, gateway_with_pool):
        """The SAME hole on the path every modern request takes — not
        introduced by this PR, but found by looking where the reported
        one was.

        Revert-check: drop that site's guard and this raises instead of
        answering 502.
        """
        url, pool = gateway_with_pool
        backend, _, entry = pool.get_or_create(None)
        pool.release(entry)
        backend.send_request = (  # type: ignore[method-assign]
            lambda line, rid, timeout: "[1, 2, 3]"
        )
        resp = _post(
            url,
            _modern_body(
                "tools/call",
                params={"name": "echo_tool", "arguments": {}},
                meta=_meta(),
            ),
            _modern_headers("tools/call", name="echo_tool"),
        )
        assert resp.status_code == 502, resp.text
        assert "malformed response" in resp.json()["error"]["message"]
