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
import sys
import threading

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
