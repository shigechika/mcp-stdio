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
import time

import httpx
import pytest

from ._legacy_child import SERVER_NAME, TOOLS
from .conftest import wait_until

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


# --- subscriptions/listen (#374) -----------------------------------------

SUBSCRIPTION_ID_KEY = "io.modelcontextprotocol/subscriptionId"


def _drive_list_changed(gateway) -> None:
    """Make the pooled child emit `notifications/tools/list_changed`.

    A MODERN notification, so it rides serve's oneway arm to the same
    per-principal pooled child every modern request in this module shares
    — which is the only way to trigger a real fan-out from outside.
    """
    resp = httpx.post(
        gateway.url,
        content=json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "notifications/list_changed_push",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            }
        ),
        headers={"MCP-Protocol-Version": MODERN_VERSION},
        timeout=20,
    )
    assert resp.status_code == 202, resp.text


@pytest.mark.timeout(90)
def test_v2_client_listen_acks_and_delivers_a_real_event(serve_gateway):
    """**#374's acceptance test.** The reference peer's own listen API.

    Entering `client.listen(...)` IS the ack assertion: it blocks until
    the ack arrives and raises if the ack is malformed. That is the
    B1-class oracle at work again — our unit tests measure the ack
    against our reading of the spec, this measures it against the first
    official implementation of the revision.

    `sub.honored` then proves the honored subset survived the A9 nesting:
    a top-level echo would leave this empty (and the client forwarding
    nothing) with no error anywhere.
    """
    import anyio

    from mcp.client import Client

    async def _drive():
        async with Client(serve_gateway.url, mode="auto") as client:
            async with client.listen(tools_list_changed=True) as sub:
                honored = dict(sub.honored) if hasattr(sub, "honored") else None
                async with anyio.create_task_group() as tg:

                    async def _fire():
                        await anyio.to_thread.run_sync(
                            _drive_list_changed, serve_gateway
                        )

                    tg.start_soon(_fire)
                    with anyio.fail_after(30):
                        async for event in sub:
                            first = event
                            break
                return {
                    "honored": honored,
                    "event": type(first).__name__,
                    "discovered": client.session.discover_result is not None,
                    "initialized": client.session.initialize_result is not None,
                }

    out = anyio.run(_drive)

    # Without this the whole test can pass on a silent legacy fallback.
    assert out["discovered"] and not out["initialized"]
    assert out["honored"], "the client saw no honored subset; the ack nested it wrong"
    assert out["event"], out


@pytest.mark.timeout(90)
def test_a_gateway_shutdown_ends_the_stream_without_losing_it(serve_factory):
    """Graceful, at the peer that decides what graceful means.

    The v2 client raises `SubscriptionLost` when a stream drops without a
    terminal frame — so "the async-for loop simply ended" is the only
    assertion that distinguishes serve's graceful teardown from an abrupt
    one, and it is the reason the terminal `resultType: "complete"` frame
    exists at all.

    A dedicated gateway: this test stops it.
    """
    import anyio

    from mcp.client import Client

    gateway = serve_factory()

    async def _drive():
        async with Client(gateway.url, mode="auto") as client:
            async with client.listen(tools_list_changed=True) as sub:
                async with anyio.create_task_group() as tg:

                    async def _stop():
                        await anyio.sleep(0.5)
                        await anyio.to_thread.run_sync(gateway.close)

                    tg.start_soon(_stop)
                    events = []
                    with anyio.fail_after(45):
                        async for event in sub:
                            events.append(event)
                    return len(events)

    # No exception escaping IS the assertion — `SubscriptionLost` here
    # would mean serve dropped the stream instead of ending it.
    assert anyio.run(_drive) == 0


@pytest.mark.timeout(60)
def test_discover_advertises_all_four_flags_the_child_supports(serve_gateway):
    """The un-strip, on raw bytes, against the child's real capabilities.

    The child advertises all four flags, and #381 completed the un-strip
    so all four are echoed: `subscriptions/listen` delivers the
    listChanged trio (#374/#382), and serve now drives per-URI
    `resources/subscribe` at the child for the fourth.

    The conditionality is the point, and it is asserted separately (a
    child WITHOUT `resources.subscribe` must still have the flag
    stripped) — see the unit suite's one-predicate pin. Here the child
    does support it, so advertising it is an honest promise rather than
    the one thing the ack refuses.
    """
    resp = httpx.post(
        serve_gateway.url,
        content=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            }
        ),
        headers={
            "MCP-Protocol-Version": MODERN_VERSION,
            "Mcp-Method": "server/discover",
        },
        timeout=20,
    )
    caps = resp.json()["result"]["capabilities"]
    assert caps["tools"]["listChanged"] is True
    assert caps["prompts"]["listChanged"] is True
    assert caps["resources"]["listChanged"] is True
    assert caps["resources"]["subscribe"] is True, caps["resources"]


@pytest.mark.timeout(120)
def test_the_auto_era_sandwich_carries_a_listchanged_end_to_end(
    serve_factory, relay_factory
):
    """Both halves of this project, pointed at each other, over listen.

    stdio client -> relay (auto era) -> serve (modern) -> legacy child.
    The relay classifies our own serve as modern, opens its own
    `subscriptions/listen` upstream, and translates what arrives back
    into the plain stdio notification its client already understands.

    This is the strictest available check on the ack's wire shape: the
    relay's own C7 validation refuses a frame that is not
    `jsonrpc: "2.0"`, is not id-less, or whose `params.notifications` is
    not an object — so a shape our unit tests merely believe is right has
    to satisfy an independent implementation before this passes.

    It also proves the un-strip END TO END: the relay only forwards a
    notification kind for a family it advertised to ITS client, and what
    it advertises comes from serve's discover. A still-stripped
    `tools.listChanged` would make the relay drop this silently.

    **The wait before driving is not decoration.** The relay opens its
    upstream listen on a BACKGROUND thread after
    `notifications/initialized`, so `initialize()` returning proves
    nothing about whether that stream exists yet — and a notification
    with no listener attached is discarded by design, which is the
    correct product behaviour and a silent test failure. This passed
    locally and failed in CI on exactly that race. Serve logs the attach,
    so the test waits for the OBSERVED attach (conftest rule 1) instead
    of driving into a window it hopes is open.

    A DEDICATED gateway rather than the module-scoped one, for that same
    signal: on a shared gateway the stderr carries every other test's
    streams too, and its drain is a BOUNDED deque, so a "the count went
    up" predicate is not stable against eviction. On a gateway of our
    own, the line appearing at all is the signal. `serve_factory` comes
    first in the signature so the relay — set up second — is torn down
    FIRST, per conftest rule 6.
    """
    gateway = serve_factory()
    client = relay_factory(gateway.port, protocol_era="auto")
    client.initialize(protocol_version=MODERN_VERSION)

    wait_until(
        lambda: any(": streaming " in line for line in gateway.stderr.lines),
        timeout=30.0,
        what="the relay's upstream listen stream to attach at serve",
        diagnose=gateway.diagnose,
    )

    _drive_list_changed(gateway)

    event = client.expect_notification("notifications/tools/list_changed", timeout=30.0)
    assert event["jsonrpc"] == "2.0"
    assert "id" not in event


def _kill_the_pooled_child(gateway) -> None:
    """Make serve's gateway-owned child exit, without touching serve."""
    resp = httpx.post(
        gateway.url,
        content=json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "exit",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            }
        ),
        headers={"MCP-Protocol-Version": MODERN_VERSION},
        timeout=20,
    )
    assert resp.status_code == 202, resp.text


@pytest.mark.timeout(120)
def test_the_relay_reads_serves_graceful_end_and_does_not_reconnect(
    serve_factory, relay_factory
):
    """The one peer where the graceful/lost distinction is a POLICY channel.

    Design amendment L1 settled that the v2 client cannot tell the two
    endings apart — an abrupt close ends its iterator cleanly, so serve's
    terminal frame is unobservable there. The RELAY can: its no-reconnect
    decision keys on a result bearing the listen id (#352), which is
    exactly the frame `_pump_listen_stream` writes on shutdown. So this
    is where the frame's *purpose* gets tested rather than its bytes.

    Three things at once, from one positive assertion:

    1. serve emitted the terminal result frame at all;
    2. it carried the relay's OWN listen id verbatim — serve mints
       replacement ids for forwarded requests, and listen is intercepted
       before that, so an id rewritten anywhere along the way would make
       the relay read a graceful end as an abrupt drop;
    3. the relay classified it as graceful and STOPPED.

    Point 3 is what a client actually feels. Without it the relay would
    reconnect-loop at 1 Hz against a gateway that is deliberately going
    away.
    """
    gateway = serve_factory()
    client = relay_factory(gateway.port, protocol_era="auto")
    client.initialize(protocol_version=MODERN_VERSION)

    wait_until(
        lambda: any(": streaming " in line for line in gateway.stderr.lines),
        timeout=30.0,
        what="the relay's upstream listen stream to attach at serve",
        diagnose=gateway.diagnose,
    )

    # SIGTERM is serve's documented shutdown path, and the path that runs
    # `modern_pool.shutdown_all()` -> graceful `close_listeners` + drain.
    gateway.close()

    wait_until(
        lambda: client.stderr.contains("closed gracefully"),
        timeout=30.0,
        what="the relay to classify serve's end as graceful",
        diagnose=lambda: f"relay stderr:\n{client.stderr.tail()}",
    )
    # And it stopped: a reconnect after a graceful end is the failure this
    # frame exists to prevent, and serve is gone, so any attempt would
    # log its own failure. Bounded quiescence (conftest rule 5).
    time.sleep(2.0)
    assert not client.stderr.contains("reconnecting"), client.stderr.tail()


@pytest.mark.timeout(120)
def test_the_relay_treats_a_dead_child_as_an_ordinary_reconnectable_drop(
    serve_factory, relay_factory
):
    """The other half of the ending table, at the same peer.

    A child dying is NOT graceful: serve stays up, so the contract is
    that the peer re-listens and refetches. Serve says that by closing
    with NO terminal frame — the absence is the signal — and the relay
    must therefore reconnect rather than give up.

    Observed at SERVE, as a second attach: that proves the relay came
    back AND that serve respawned a child for it, which is the whole
    recovery path rather than half of it.
    """
    gateway = serve_factory()
    client = relay_factory(gateway.port, protocol_era="auto")
    client.initialize(protocol_version=MODERN_VERSION)

    def _attaches() -> int:
        return sum(1 for line in gateway.stderr.lines if ": streaming " in line)

    wait_until(
        lambda: _attaches() >= 1,
        timeout=30.0,
        what="the relay's upstream listen stream to attach at serve",
        diagnose=gateway.diagnose,
    )

    _kill_the_pooled_child(gateway)

    wait_until(
        lambda: _attaches() >= 2,
        timeout=60.0,
        what="the relay to re-listen after the abrupt end",
        diagnose=lambda: f"{gateway.diagnose()}\nrelay stderr:\n{client.stderr.tail()}",
    )
    # Recovered for real, not just reconnected: the fresh child serves
    # the listChanged the reconnected stream subscribed to.
    _drive_list_changed(gateway)
    event = client.expect_notification("notifications/tools/list_changed", timeout=30.0)
    assert event["jsonrpc"] == "2.0"
