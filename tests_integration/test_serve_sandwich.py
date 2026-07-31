"""The gateway sandwich: stdio client -> relay -> serve -> legacy child (#270 P3-0).

Both halves of this project, pointed at each other, with a real stdio
client on one end and a real stdio MCP child on the other:

    StdioClient --stdio--> `mcp-stdio` relay --HTTP--> `mcp-stdio serve` --stdio--> child

WHY it belongs in P3-0 rather than later. The relay and serve are
developed against separate test suites and separate mental models of the
same spec, so each can drift toward its own reading and stay green. The
sandwich is the only place a disagreement between them becomes a failing
test rather than a field report — the same argument #367 makes for the
reference peer, applied to our two implementations of opposite sides of
one wire.

Its Phase 3 job is narrower and load-bearing: `--protocol-era legacy`
here is the AC2 control. P3-A and P3-B change what serve does with
MODERN-marked traffic; this test says a legacy relay in front of serve
keeps working while that happens. P3-B then adds the `auto`-era variant
(the re-scope's "auto-era gateway sandwich"), where the relay classifies
our own serve as modern and its fail-closed `ttlMs` merge cross-validates
discover — that one needs modern dispatch to exist, so it is not here.

Determinism: the relay is driven through the same `StdioClient` #367
built, and every wait is bounded. Teardown is relay-first, as conftest
rule 6 requires (the relay holds an HTTP connection to serve) — and it
holds by SCOPE, not by argument order: `relay_factory` is
function-scoped and `serve_gateway` module-scoped, so the relay is torn
down at the end of each test while the gateway outlives the module.
Argument order governs only same-scope fixtures and is irrelevant here.
"""

from __future__ import annotations

import json

import pytest

from ._legacy_child import INITIALIZE_RESULT, LEGACY_PROTOCOL_VERSION, TOOLS


def test_full_sandwich_completes_a_tools_flow(serve_gateway, relay_factory):
    """One end-to-end tools flow through the whole sandwich.

    Every hop is exercised for real: the client's `initialize` reaches the
    child and its result comes back; the relay adopts the `Mcp-Session-Id`
    serve minted and keeps presenting it (without which the second request
    would be serve's 400-sessionless path, so this is a genuine assertion
    about session round-tripping, not just about tools); and `tools/call`
    returns the child's own payload unaltered end to end.
    """
    client = relay_factory(serve_gateway.port, protocol_era="legacy")

    init = client.initialize(protocol_version=LEGACY_PROTOCOL_VERSION)
    # The child's InitializeResult in FULL, unaltered by either gateway —
    # not the relay's or serve's invention, and not a spot check that
    # would miss one rewritten field (#370 review R1F1).
    assert init == INITIALIZE_RESULT

    listed = client.request("tools/list")
    assert listed["tools"] == TOOLS
    # The legacy face carries no modern stamping at any hop.
    assert "resultType" not in listed
    assert "ttlMs" not in listed and "cacheScope" not in listed

    called = client.request(
        "tools/call", {"name": "echo", "arguments": {"text": "through the sandwich"}}
    )
    payload = json.loads(called["content"][0]["text"])
    assert payload["echoed"] == {"text": "through the sandwich"}
    assert called["isError"] is False


def test_sandwich_surfaces_a_child_error_under_the_clients_own_id(
    serve_gateway, relay_factory
):
    """A child-side JSON-RPC error survives both hops with its own code.

    Pins that neither gateway re-wraps it: the relay does not turn it into
    a transport error and serve does not replace it with its own -32000.
    Under the id the CLIENT sent, which is the correlation both gateways
    are responsible for preserving.
    """
    client = relay_factory(serve_gateway.port, protocol_era="legacy")
    client.initialize(protocol_version=LEGACY_PROTOCOL_VERSION)

    req_id = client.send_request("tools/call", {"name": "nope", "arguments": {}})
    error = client.expect_error(req_id)
    assert error["code"] == -32602


@pytest.mark.timeout(60)
def test_auto_era_sandwich_classifies_our_serve_as_modern(serve_gateway, relay_factory):
    """The other half of the sandwich, reserved by P3-0 and delivered here.

    `--protocol-era auto` makes the RELAY probe our own serve with
    `server/discover`. That closes the loop in a way neither side's own
    tests can: the relay is strict in both directions, so serve's discover
    has to satisfy a real consumer that was written independently of it.

    Three independent checks ride on one flow:

    1. the relay's era probe must classify serve as MODERN — it demands an
       object result, so a malformed discover falls back to legacy and the
       stderr below says so;
    2. the relay's modern POSTs must pass serve's OWN P3-A ladder — both
       gateways have to agree on `_meta`, `MCP-Protocol-Version`,
       `Mcp-Method` and the `Mcp-Name` sentinel, and a disagreement is a
       -32020 rather than a silent degradation;
    3. the relay's cacheable-list merge FAILS CLOSED on a page with a
       missing or malformed `ttlMs`/`cacheScope` (#350), so a successful
       `tools/list` through it is independent evidence that serve stamped
       the hints correctly — evidence the v2 client cannot give for the
       auto-pagination path.
    """
    client = relay_factory(serve_gateway.port, protocol_era="auto")
    client.initialize(protocol_version=LEGACY_PROTOCOL_VERSION)

    listed = client.request("tools/list")
    assert [tool["name"] for tool in listed["tools"]] == [t["name"] for t in TOOLS]

    called = client.request(
        "tools/call", {"name": "echo", "arguments": {"text": "auto era"}}
    )
    payload = json.loads(called["content"][0]["text"])
    assert payload["echoed"] == {"text": "auto era"}

    # The probe's verdict, from the relay's own log. Asserted because a
    # legacy classification would still make every line above pass — serve
    # is dual-era, so the legacy path answers too.
    assert client.stderr.contains("protocol era: modern"), client.stderr.tail()
