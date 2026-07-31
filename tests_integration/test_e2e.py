"""Six end-to-end scenarios against python-sdk v2.0.0, the reference peer.

Each pins one #270 Phase 2 subsystem that was previously verified only
against this project's own mocks. Run order is 1 -> 6; scenarios 1 and 2 are
readiness gates for the rest.

A real discrepancy found here is a STOP-AND-REPORT on #367/#270 (the A9/D1
precedent), never a quiet adjustment inside a scenario.
"""

from __future__ import annotations

from . import _reference_server
from .conftest import wait_until

RESOURCE_URI = _reference_server.RESOURCE_URI


def test_era_probe_classifies_the_v2_server_as_modern(harness_server, relay_factory):
    """Scenario 1 — Phase 1 era detection, against the reference peer.

    The relay's `--protocol-era auto` probe sends `server/discover` and
    classifies from the reply. Until now "a v2 server classifies as modern"
    was a source-reading; here it is an observation.

    Both halves are asserted because neither alone discriminates: a v2
    server answers a legacy `initialize` too, so a successful handshake
    proves only connectivity. The stderr marker is what names the branch
    the relay actually took (`run()` logs it unconditionally on the auto
    path, whichever way the probe went).
    """
    client = relay_factory(harness_server.port)
    result = client.initialize()

    # The relay SYNTHESIZES this locally on the modern era — the modern wire
    # has no `initialize` — and answers in the client's own 2025-06-18
    # dialect.
    assert result["protocolVersion"] == "2025-06-18"
    assert result["serverInfo"]["name"] == _reference_server.SERVER_NAME
    wait_until(
        lambda: client.stderr.contains("protocol era: modern (auto-detected)"),
        timeout=5.0,
        what="the relay's era classification marker",
    )
    assert not client.stderr.contains("protocol era: legacy")


def test_initialize_tools_list_and_call(harness_server, relay_factory):
    """Scenario 2 — AC3 header layer, `_meta` injection, `resultType`.

    Every modern POST carries `Mcp-Method`/`Mcp-Name` headers and
    `params._meta`. A server that rejected either would fail here, which is
    the only way to find out short of reading its source: the relay's own
    tests can only assert that it SENT them.

    `resultType` is the modern envelope field, and the observed behaviour is
    PASS-THROUGH, not translation: the relay interprets it only to spot
    `input_required` (the MRTR branch, scenario 3) and otherwise forwards
    the result verbatim, server `_meta` included. That is sound — MCP
    results are open, so a 2025-era client ignores fields it does not know —
    and it is pinned below because it is the kind of thing a future
    "normalize the envelope" change would break silently.
    """
    client = relay_factory(harness_server.port)
    client.initialize()

    tools = client.request("tools/list")
    names = {tool["name"] for tool in tools["tools"]}
    assert {"add", "guarded_op", "wait_for_release"} <= names

    result = client.request(
        "tools/call", {"name": "add", "arguments": {"a": 2, "b": 3}}
    )
    assert result["content"][0]["text"] == "5"
    assert result["isError"] is False
    assert result["structuredContent"] == {"result": 5}
    # Pass-through, pinned (see the docstring): the modern envelope reaches
    # the 2025-era client untouched, and the relay does not choke on it.
    assert result["resultType"] == "complete"
    assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == (
        _reference_server.SERVER_NAME
    )


def test_mrtr_full_loop_under_the_original_id(harness_server, relay_factory):
    """Scenario 3 — PR C (#356): `inputRequests`/`inputResponses` + retry.

    The most hand-modeled shapes in Phase 2, and the designated watchpoint.
    The reference peer answers `tools/call` with an `InputRequiredResult`
    (`resultType: "input_required"`, an `inputRequests` map keyed
    `module:qualname`, and an opaque `requestState`); the relay mints the
    entry onto stdout as a plain 2025-era `elicitation/create` request,
    collects this client's answer, and re-POSTs the ORIGINAL call with
    `inputResponses` — so the final result must arrive under the id the
    client used in the first place, with no trace of the round-trip.
    """
    client = relay_factory(harness_server.port)
    client.initialize()

    call_id = client.send_request(
        "tools/call", {"name": "guarded_op", "arguments": {"path": "/tmp/x"}}
    )

    # The relay mints this; the reference peer never sends a server-initiated
    # request on a modern connection (the SDK raises `NoBackChannelError`).
    minted = client.expect_request("elicitation/create", timeout=10.0)
    assert "Really operate on /tmp/x?" in minted["params"]["message"]
    assert minted["params"]["requestedSchema"]["properties"]["ok"]["type"] == "boolean"
    # `mode: "form"` is stripped for a 2025-era client, which predates the
    # discriminator entirely and must see the shape it has always known.
    assert "mode" not in minted["params"]
    # The minted id lives in the relay's reserved namespace, so it can never
    # collide with an id this client allocated.
    assert minted["id"] != call_id

    client.respond(minted["id"], {"action": "accept", "content": {"ok": True}})

    result = client.expect_result(call_id, timeout=10.0)
    assert result["content"][0]["text"] == "done /tmp/x"


def test_subscribe_publish_and_forward(harness_server, relay_factory):
    """Scenario 4 — PR B (#358), Design A9, the highest-risk interop point.

    Spec rev 2026-07-28 deleted `resources/subscribe` from the wire, so the
    relay answers it locally and expresses the subscription as the
    `notifications.resourceSubscriptions` filter on its long-lived
    `subscriptions/listen` POST. A9 was caught by cross-checking the
    REQUEST side against generated types; the ack-ECHO side (the relay
    reads the honored subset out of the same nested place) had never met a
    real server. A mismatch there is a silent double no-op: updates simply
    never arrive.
    """
    client = relay_factory(harness_server.port)
    client.initialize()

    # Answered locally with the legacy EmptyResult; nothing is forwarded.
    assert client.request("resources/subscribe", {"uri": RESOURCE_URI}) == {}

    # The subscribe re-opens the resource listen stream, so the server may
    # not have the new filter yet. Publishing until the notification lands
    # keeps this deterministic without asserting on timing (rule 4).
    received: list[dict] = []

    def _published_and_forwarded() -> bool:
        harness_server.publish_resource_updated()
        try:
            received.append(
                client.expect_notification(
                    "notifications/resources/updated", timeout=0.5
                )
            )
        except TimeoutError:
            return False
        return True

    wait_until(
        _published_and_forwarded,
        timeout=15.0,
        what="a resources/updated notification forwarded downstream",
    )
    # Assert on the notification that was actually matched, not on whatever
    # a later drain happens to hold — a drain can legitimately come back
    # empty, which would make these checks silently vacuous.
    message = received[-1]
    assert message["params"]["uri"] == RESOURCE_URI
    # The relay must NOT leak the subscription id `_meta` the SDK stamps on
    # every listen frame: a 2025-era client never saw one.
    assert "io.modelcontextprotocol/subscriptionId" not in message["params"].get(
        "_meta", {}
    )


def test_listen_graceful_end_does_not_reconnect(dedicated_server, relay_factory):
    """Scenario 5 — PR A (#352) graceful-end signals.

    Its own server: ending every listen stream would break later tests on
    the shared one.

    `ListenHandler.close()` is the SDK's documented graceful-closure hook —
    each stream flushes and sends its `SubscriptionsListenResult` as the
    final frame, "telling clients the stream ended deliberately rather than
    dropping". #367's design allowed a loosened form if no in-server hook
    existed; one does, so this asserts the STRONG form: the relay
    recognizes the signal, stops, and does NOT reconnect.

    The no-reconnect half is a bounded quiescence check (rule 5), justified
    by the PR A record: the relay reconnects forever on an ABRUPT drop, so
    "no further listen POST" is the only thing that distinguishes a
    recognized graceful end from a drop it happened to be slow about.
    """
    harness = dedicated_server()
    client = relay_factory(harness.port)
    client.initialize()
    assert client.request("resources/subscribe", {"uri": RESOURCE_URI}) == {}

    # Prove the stream is actually up before ending it, so a pass cannot
    # come from having closed nothing.
    def _forwarding() -> bool:
        harness.publish_resource_updated()
        try:
            client.expect_notification("notifications/resources/updated", timeout=0.5)
        except TimeoutError:
            return False
        return True

    wait_until(_forwarding, timeout=15.0, what="the listen stream to be established")

    harness.end_listen_streams()
    wait_until(
        lambda: client.stderr.contains("closed gracefully"),
        timeout=10.0,
        what="the relay to recognize the graceful end",
        diagnose=lambda: f"relay stderr tail:\n{client.stderr.tail()}",
    )

    # Clear the decks BEFORE the quiescence check, or it is unsound. Two
    # legitimate sources of an in-flight update survive the establishment
    # probe: the probe publishes once per poll, so the iteration that
    # succeeded may have left an earlier duplicate still travelling; and
    # `ListenHandler.close()` explicitly "drains its buffered events" before
    # sending the final frame, so a buffered publish is forwarded BY the
    # graceful end itself. Neither says anything about a reconnect, which is
    # the only thing the check below is about.
    client.drain(0.5)

    # Bounded quiescence: a reconnect would produce a fresh ack and, with it,
    # a fresh forwarded update for the publish below. Neither may appear.
    before = len(client.stderr.lines)
    harness.publish_resource_updated()
    late = [
        m
        for m in client.drain(1.0)
        if m.get("method") == "notifications/resources/updated"
    ]
    assert late == []
    after = list(client.stderr.lines)[before:]
    assert not any("reopening" in line for line in after)

    # Still drivable on the ordinary request path — the graceful end stops
    # ONE stream, not the session.
    assert (
        client.request("tools/call", {"name": "add", "arguments": {"a": 1, "b": 1}})[
            "content"
        ][0]["text"]
        == "2"
    )


def test_cancel_aborts_the_in_flight_post(dedicated_server, relay_factory):
    """Scenario 6 — PR D (#362): disconnect-as-cancellation, end to end.

    Its own server: the parked tool call and the aborted connection are
    state later tests should not inherit.

    "Streamable HTTP: Closing the SSE response stream is the cancellation
    signal. The server MUST treat a client disconnect as cancellation of
    that request." So a `notifications/cancelled` on stdin must abort the
    matching in-flight POST rather than being forwarded upstream — and the
    proof has to come from the SERVER: the tool's own cancellation arm
    firing is the only evidence the disconnect was read as a cancellation
    rather than as a dropped connection.

    The three not-covered windows recorded in PR D are deliberately NOT
    probed here: landing a cancel inside one of them against a real server
    needs instrumentation this harness should not have. They stay unit-
    pinned, and probing moves to the torture follow-up (#367 design, change
    2).
    """
    harness = dedicated_server()
    client = relay_factory(harness.port)
    client.initialize()

    # `progressToken` is a 2025-era `params._meta` field the relay MERGES
    # its modern `_meta` into rather than replacing. The tool needs it to
    # emit — see `wait_for_release` for why emitting is what puts the relay
    # past the pre-headers window.
    call_id = client.send_request(
        "tools/call",
        {"name": "wait_for_release", "_meta": {"progressToken": "harness/cancel"}},
    )
    # Gate the cancel on the forwarded progress notification. It is the only
    # DOWNSTREAM-observable proof that the SSE response headers arrived and
    # the relay published the response handle — a server-side "handler
    # entered" flag is not enough, because `report_progress` returns before
    # those bytes have reached the relay. Cancelling early would land in PR
    # D's pre-headers window: one of the three documented not-covered
    # windows, explicitly out of scope here (#367 design, change 2), so the
    # test would flake on something it is not testing.
    progress = client.expect_notification("notifications/progress", timeout=10.0)
    assert progress["params"]["progressToken"] == "harness/cancel"
    client.notify("notifications/cancelled", {"requestId": call_id})

    wait_until(
        harness.cancelled.is_set,
        timeout=10.0,
        what="the reference peer's tool to observe anyio cancellation",
        # On failure the FIRST question is whether the relay aborted at all.
        # "cancelling id N: closing the in-flight upstream POST" present means
        # the relay did its job and the disconnect did not become a
        # cancellation server-side; absent means the relay never acted.
        diagnose=lambda: (
            f"relay aborted the POST: {client.stderr.contains('closing the in-flight')}"
            f"\nrelay stderr tail:\n{client.stderr.tail()}"
        ),
    )

    # Bounded quiescence (rule 5), justified by the PR D record: a cancelled
    # id must never produce a late response on stdout — the cancel tracker
    # drops one even if the transport raced.
    late = [m for m in client.drain(1.0) if m.get("id") == call_id]
    assert late == []
