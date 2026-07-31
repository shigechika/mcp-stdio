"""What serve does with MODERN-marked traffic (#270 Phase 3, P3-0 -> P3-A).

THIS FILE IS EXPECTED TO CHANGE, once per Phase 3 PR. That is why it is
not in `test_serve_legacy_pin.py`, whose charter is the opposite: that
suite must stay green with ZERO diffs, and a single test inside it that
is designed to move would destroy the property — once one diff is
legitimate, every diff needs adjudication instead of being prima facie a
bug.

The split is the whole point:

- `test_serve_legacy_pin.py` — the AC2 invariant. A diff there is a bug
  until proven otherwise.
- this file — the moving picture. A diff here is the DELIVERABLE of the
  PR, and its ABSENCE in a PR claiming to ship one is itself the finding.

**P3-0** recorded the before-picture: serve had no modern face at all, so
a request carrying modern `_meta` and a `server/discover` both fell into
the ordinary sessionless-POST path and got 400 `-32000`.

**P3-A** (this revision) gives serve a modern REQUEST PLANE: the D5 era
predicate plus the O6-O10 validation ladder. Invalid modern traffic now
earns real codes — `-32602`, `-32020`, `-32022` — while the legacy path
is untouched. What P3-A deliberately did NOT ship was modern DISPATCH — a request
passing every rung still fell through to the same 400 `-32000`
"Mcp-Session-Id required". That seam is what P3-B replaced.

**P3-B** (this revision) flipped the seam: `server/discover` is answered
with a synthesized `resultType: "complete"` DiscoverResult, and validated
modern requests are dispatched statelessly against a gateway-owned child.
Every `-32000` fallthrough assertion P3-A left here has moved, which is
what a change-EXPECTED file is for.

The unit-level ladder coverage lives in `tests/test_server_modern.py`
(30 tests, every rung and every boundary). These are the END-TO-END
confirmations through a real `mcp-stdio serve` subprocess: one case per
rejection code, the fallthrough, and the keep-alive contract.
"""

from __future__ import annotations

import json
import re
import socket

import httpx
import pytest

from ._legacy_child import SERVER_NAME, TOOLS

MODERN_VERSION = "2026-07-28"
META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CAPS = "io.modelcontextprotocol/clientCapabilities"

# The codes serve's modern request plane emits as of P3-A. `-32000` is the
# LEGACY rejection, kept here for the fallthrough assertion: seeing it
# proves the ladder let a request through rather than answering it.
INVALID_PARAMS = -32602
HEADER_MISMATCH = -32020
UNSUPPORTED_VERSION = -32022
LEGACY_ERROR = -32000


def _meta(version: object = MODERN_VERSION) -> dict:
    return {META_VERSION: version, META_CAPS: {}}


def _body(method: str = "tools/list", req_id: object = 1, **params) -> dict:
    merged = {"_meta": params.pop("meta", _meta())}
    merged.update(params)
    return {"jsonrpc": "2.0", "id": req_id, "method": method, "params": merged}


def _headers(method: str | None = "tools/list", version: str | None = MODERN_VERSION):
    headers = {}
    if version is not None:
        headers["MCP-Protocol-Version"] = version
    if method is not None:
        headers["Mcp-Method"] = method
    return headers


def _assert_rejected(resp: httpx.Response, code: int, req_id: object = 1) -> dict:
    """The contract every ladder rejection shares, end to end.

    The `Mcp-Session-Id` absence is the one worth stating out loud: the
    ladder runs BEFORE session resolution, so a rejection must never look
    like it opened a session — and this assertion is what notices if the
    hook is ever moved below that block.
    """
    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["error"]["code"] == code, body
    assert body["id"] == req_id, body
    assert "mcp-session-id" not in resp.headers, dict(resp.headers)
    return body["error"]


@pytest.mark.timeout(45)
def test_modern_rejections_carry_their_own_codes(serve_factory):
    """One end-to-end case per code the P3-A ladder can emit.

    A dedicated gateway rather than the module-scoped one: this is the
    file most likely to be rewritten by a later PR, and it must not leave
    a shared fixture in a state that rewrite could disturb.
    """
    gateway = serve_factory()

    # -32602 — modern by `server/discover`'s method alone, but with no
    # `_meta` at all. The discover arm of the era predicate classifies it;
    # rung 1 rejects it. (P3-0 asserted -32000 here.)
    discover = gateway.post({"jsonrpc": "2.0", "id": 1, "method": "server/discover"})
    _assert_rejected(discover, INVALID_PARAMS)

    # -32602 — `_meta` present but incomplete. `clientCapabilities` is
    # REQUIRED; `clientInfo` is SHOULD-only and never rejected on.
    incomplete = gateway.post(
        _body(meta={META_VERSION: MODERN_VERSION}), headers=_headers()
    )
    error = _assert_rejected(incomplete, INVALID_PARAMS)
    assert META_CAPS in error["message"]

    # -32020 — **AC4**: the header and the body disagree about the
    # revision. The message names the header and echoes NEITHER value.
    mismatch = gateway.post(_body(), headers=_headers(version="2025-06-18"))
    error = _assert_rejected(mismatch, HEADER_MISMATCH)
    assert "MCP-Protocol-Version" in error["message"]
    assert "2025-06-18" not in error["message"]
    assert MODERN_VERSION not in error["message"]
    # The schema gives -32020 no `data`.
    assert "data" not in error

    # -32020 — the required `Mcp-Method` header is absent.
    no_method = gateway.post(_body(), headers=_headers(method=None))
    _assert_rejected(no_method, HEADER_MISMATCH)

    # -32020 — `Mcp-Name` disagrees with the body's `params.name`.
    bad_name = gateway.post(
        _body("tools/call", name="echo"),
        headers={**_headers("tools/call"), "Mcp-Name": "not-echo"},
    )
    _assert_rejected(bad_name, HEADER_MISMATCH)

    # -32020 — a malformed base64 sentinel. It decodes to None, which
    # never equals the body value, so a corrupt header lands here instead
    # of needing a code of its own or escaping as a 500.
    bad_sentinel = gateway.post(
        _body("tools/call", name="echo"),
        headers={**_headers("tools/call"), "Mcp-Name": "=?base64?not-base64!!?="},
    )
    _assert_rejected(bad_sentinel, HEADER_MISMATCH)

    # -32022 — a revision serve does not implement. `data` is
    # SCHEMA-MANDATED here: without `supported` a client has nothing to
    # renegotiate toward. Asserted on the parsed shape, not a substring.
    unsupported = gateway.post(
        _body(meta=_meta("2099-01-01")), headers=_headers(version="2099-01-01")
    )
    error = _assert_rejected(unsupported, UNSUPPORTED_VERSION)
    assert error["data"]["supported"] == [MODERN_VERSION]
    assert error["data"]["requested"] == "2099-01-01"


@pytest.mark.timeout(45)
def test_a_valid_modern_request_is_dispatched_statelessly(serve_factory):
    """P3-B's seam flip, end to end — and the diff here IS the deliverable.

    P3-A's version of this test asserted the 400 `-32000` fallthrough and
    was labelled "P3-A ships ZERO modern dispatch". The flip replaced that
    seam with stateless dispatch, so a request satisfying every rung is
    now SERVED: no `initialize`, no session, and none sent back.

    Spec: "Servers MUST NOT rely on prior requests over the same
    connection to establish context (e.g., capabilities, protocol
    version, client identity)." Nothing preceded this request.
    """
    gateway = serve_factory()
    resp = gateway.post(_body(), headers=_headers())
    assert resp.status_code == 200, resp.text
    assert "mcp-session-id" not in resp.headers, dict(resp.headers)
    result = resp.json()["result"]
    assert [tool["name"] for tool in result["tools"]] == [t["name"] for t in TOOLS]
    # Stamped, asserted on the RAW wire — the v2 client defaults these on
    # its own models, so only the bytes prove serve emitted them.
    assert result["resultType"] == "complete"
    assert result["ttlMs"] >= 0
    assert result["cacheScope"] == "private"
    assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == SERVER_NAME


@pytest.mark.timeout(45)
def test_discover_is_synthesized_by_serve(serve_factory):
    """`server/discover` is answered by serve, never forwarded.

    P3-A pinned this as -32602 (no `_meta`); with `_meta` present it is
    now a real DiscoverResult. Both required fields are asserted because
    the v2 client silently falls back to `initialize` without them —
    discovery "succeeds" while the modern path never engages.
    """
    gateway = serve_factory()
    resp = gateway.post(_body("server/discover"), headers=_headers("server/discover"))
    assert resp.status_code == 200, resp.text
    result = resp.json()["result"]
    assert result["supportedVersions"] == [MODERN_VERSION]
    assert isinstance(result["capabilities"], dict)
    assert result["resultType"] == "complete"
    assert result["cacheScope"] == "private"
    assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == SERVER_NAME


@pytest.mark.timeout(45)
def test_a_modern_notification_is_acknowledged(serve_factory):
    """202, sessionless (§4 Q4 adopted).

    P3-A left modern notifications on the legacy fallthrough, where a
    sessionless one earned 400 because session resolution ran first.
    """
    gateway = serve_factory()
    body = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {"_meta": _meta()},
    }
    resp = gateway.post(body)
    assert resp.status_code == 202
    assert resp.content == b""


@pytest.mark.timeout(45)
def test_a_modern_rejection_drains_the_body_so_keep_alive_survives(serve_factory):
    """The sibling of the legacy pin's raw-socket drain test.

    P3-A adds several new 4xx early returns, and the re-scope's risk
    table names exactly this as their hazard: on HTTP/1.1 keep-alive,
    leftover body bytes are parsed as the NEXT request line ("Bad request
    syntax"). The new returns inherit the contract by construction —
    validation sits after `do_POST`'s body read — and this proves it for
    a MODERN rejection specifically, which the legacy pin cannot cover.

    Over a raw socket with two pipelined requests, for the same reason
    the legacy sibling is: a connection pool is free to open a second
    connection and pass the test vacuously without exercising reuse.
    """
    gateway = serve_factory()
    sid = gateway.open_session()

    # A modern request with a padded body that will be REJECTED (-32020,
    # header/body version mismatch), followed by a legacy request that
    # must be answered normally on the same connection.
    rejected = json.dumps(_body(**{"pad": "x" * 400}))
    accepted = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})

    def _frame(body: str, extra: str = "") -> bytes:
        return (
            f"POST /mcp HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"{extra}"
            f"Content-Length: {len(body)}\r\n\r\n{body}"
        ).encode("utf-8")

    sock = socket.create_connection(("127.0.0.1", gateway.port), timeout=10)
    try:
        sock.sendall(
            _frame(
                rejected,
                extra=(
                    "MCP-Protocol-Version: 2025-06-18\r\nMcp-Method: tools/list\r\n"
                ),
            )
        )
        sock.sendall(_frame(accepted, extra=f"Mcp-Session-Id: {sid}\r\n"))
        sock.settimeout(10)
        data = b""
        while data.count(b"HTTP/1.1 ") < 2:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
        gateway.delete(sid=sid)

    text = data.decode("utf-8", "replace")
    # Scanned with a regex, not `splitlines()`: the second response's
    # status line begins immediately after the first response's body.
    assert re.findall(r"HTTP/1\.1 (\d{3})", text)[:2] == ["400", "200"], text[:800]
    assert "Bad request syntax" not in text
    # And the first response really was the MODERN rejection, not some
    # other 400 that happens to keep the connection alive.
    assert f'"code": {HEADER_MISMATCH}' in text or f'"code":{HEADER_MISMATCH}' in text
