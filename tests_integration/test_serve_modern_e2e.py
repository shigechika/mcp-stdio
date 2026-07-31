"""AC1: the reference peer's CLIENT drives our serve, modern end to end (#270 P3-B).

This is the acceptance test #270 closes on. Everything else in Phase 3
was measured against our own reading of the spec; this measures serve
against the first official implementation of spec rev 2026-07-28 — the
A9 blind-spot insurance, now pointed at the server side.

**The oracle has one trap, and the whole file is shaped around it.** When
the v2 client cannot validate a `DiscoverResult`, it does not fail: it
SILENTLY FALLS BACK to a legacy `initialize` handshake and carries on.
Verified against the real client during design — a discover result
missing `capabilities` produced `initialize` +
`notifications/initialized` + `tools/list`, all successful, with
`discover_result` left None. So a test that asserts only "the calls
worked" passes while the modern path never engaged at all.

Every test here therefore asserts `session.discover_result is not None`
(and `initialize_result is None`) — the only evidence that the client
ended MODERN.

**And the client is only a partial stamping oracle**, in a way the design
did not anticipate and this file records: on a modern-negotiated session
it REQUIRES `resultType`/`ttlMs`/`cacheScope` on the cacheable ops
(a bare `{"tools": []}` raises `ValidationError: 3 validation errors for
ListToolsResult`), but it tolerates their absence elsewhere because the
models default them. So liveness here proves the six are stamped, and the
raw-wire assertions below prove the rest — `resultType` on `tools/call`,
the serverInfo `_meta`, and the deliberate ABSENCE of caching hints on
`tools/call`.

Practicalities: the v2 client is async and the suite installs no anyio
pytest plugin, so each test runs one `anyio.run(...)`. Client-side
caching is on by default, so each operation is called once.
"""

from __future__ import annotations

import json

import httpx
import pytest

from ._legacy_child import SERVER_NAME, TOOLS

MODERN_VERSION = "2026-07-28"
SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo"


def _run(coro_fn):
    """One async client session, driven from a sync test."""
    import anyio

    return anyio.run(coro_fn)


@pytest.mark.timeout(60)
def test_v2_client_completes_discover_tools_list_and_call(serve_gateway):
    """**AC1.** No initialize, no session — discover, list, call.

    `mode="auto"` makes the client emit `server/discover` and, on
    success, no `initialize` at all.
    """
    from mcp.client import Client

    async def _drive():
        async with Client(serve_gateway.url, mode="auto") as client:
            listed = await client.list_tools()
            called = await client.call_tool("echo", {"text": "over the wire"})
            return {
                "tools": [t.name for t in listed.tools],
                "ttl_ms": listed.ttl_ms,
                "cache_scope": listed.cache_scope,
                "content": called.content[0].text,
                "discovered": client.session.discover_result is not None,
                "initialized": client.session.initialize_result is not None,
                "supported": list(client.session.discover_result.supported_versions),
            }

    out = _run(_drive)

    # THE assertion. Without it every other line here passes on a silent
    # legacy fallback.
    assert out["discovered"], (
        "the client fell back to legacy; serve's discover failed validation"
    )
    assert not out["initialized"], (
        "an initialize handshake happened; this was not a modern flow"
    )

    assert out["supported"] == [MODERN_VERSION]
    assert out["tools"] == [tool["name"] for tool in TOOLS]
    # The child echoes its arguments back inside an `echoed` wrapper.
    assert json.loads(out["content"])["echoed"] == {"text": "over the wire"}
    # The client parsed the caching hints serve stamped — and would have
    # raised ValidationError had they been missing.
    assert out["ttl_ms"] >= 0
    assert out["cache_scope"] == "private"


@pytest.mark.timeout(60)
def test_the_wire_carries_every_stamp(serve_gateway):
    """Stamping asserted on RAW BYTES, not through the client's models.

    The client defaults `resultType`/`ttlMs`/`cacheScope` on every model,
    so a `tools/call` missing `resultType` would sail through it. Only the
    wire shows what serve actually emitted — which is what a conformance
    claim rests on.
    """
    meta = {
        "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    base = {"MCP-Protocol-Version": MODERN_VERSION}

    def _post(method, params=None, name=None):
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": {**(params or {}), "_meta": meta},
        }
        headers = {**base, "Mcp-Method": method}
        if name is not None:
            headers["Mcp-Name"] = name
        return httpx.post(
            serve_gateway.url, content=json.dumps(body), headers=headers, timeout=20
        ).json()["result"]

    discover = _post("server/discover")
    assert discover["resultType"] == "complete"
    assert discover["supportedVersions"] == [MODERN_VERSION]
    assert isinstance(discover["capabilities"], dict)
    assert discover["ttlMs"] >= 0 and discover["cacheScope"] == "private"
    assert discover["_meta"][SERVER_INFO_KEY]["name"] == SERVER_NAME

    listed = _post("tools/list")
    assert listed["resultType"] == "complete"
    assert listed["ttlMs"] >= 0 and listed["cacheScope"] == "private"
    assert listed["_meta"][SERVER_INFO_KEY]["name"] == SERVER_NAME

    called = _post(
        "tools/call", {"name": "echo", "arguments": {"text": "x"}}, name="echo"
    )
    # `resultType` yes; caching hints NO — `CallToolResult` is not a
    # CacheableResult, and the v2 client's model has no such fields, so
    # stamping them would be inventing wire data.
    assert called["resultType"] == "complete"
    assert "ttlMs" not in called and "cacheScope" not in called
    assert called["_meta"][SERVER_INFO_KEY]["name"] == SERVER_NAME


@pytest.mark.timeout(60)
def test_the_modern_flow_mints_no_session(serve_gateway):
    """A modern exchange leaves no session behind, and echoes none.

    Spec, to a server serving the modern era: "ignore it, and do not mint
    or echo session IDs." The v2 client never sends one anyway (its
    capture is gated on an `initialize` response), so this pins serve's
    half of the contract.
    """
    meta = {
        "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    resp = httpx.post(
        serve_gateway.url,
        content=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {"_meta": meta},
            }
        ),
        headers={"MCP-Protocol-Version": MODERN_VERSION, "Mcp-Method": "tools/list"},
        timeout=20,
    )
    assert resp.status_code == 200
    assert "mcp-session-id" not in resp.headers, dict(resp.headers)
