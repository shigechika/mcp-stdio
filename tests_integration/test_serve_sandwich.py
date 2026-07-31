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
built, every wait is bounded, and teardown is relay-first (the relay
holds an HTTP connection to serve) exactly as conftest rule 6 requires —
`relay_factory` is requested AFTER `serve_gateway`, so pytest's
reverse-order teardown closes the relay first.
"""

from __future__ import annotations

import json

from ._legacy_child import LEGACY_PROTOCOL_VERSION, SERVER_NAME, TOOLS


def test_full_sandwich_completes_a_tools_flow(serve_gateway, relay_factory):
    """One end-to-end tools flow through the whole sandwich.

    Every hop is exercised for real: the client's `initialize` reaches the
    child and its result comes back; the relay adopts the `Mcp-Session-Id`
    serve minted and keeps presenting it (without which the second request
    would be serve's 400-sessionless path, so this is a genuine assertion
    about session round-tripping, not just about tools); and `tools/call`
    returns the child's own payload unaltered end to end.
    """
    client = relay_factory(
        serve_gateway.port, protocol_era="legacy", extra_args=["--no-cancel-filter"]
    )

    init = client.initialize(protocol_version=LEGACY_PROTOCOL_VERSION)
    # The child's InitializeResult, not the relay's or serve's invention.
    assert init["protocolVersion"] == LEGACY_PROTOCOL_VERSION
    assert init["serverInfo"]["name"] == SERVER_NAME

    listed = client.request("tools/list")
    assert [tool["name"] for tool in listed["tools"]] == [
        tool["name"] for tool in TOOLS
    ]
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
    client = relay_factory(
        serve_gateway.port, protocol_era="legacy", extra_args=["--no-cancel-filter"]
    )
    client.initialize(protocol_version=LEGACY_PROTOCOL_VERSION)

    req_id = client.send_request("tools/call", {"name": "nope", "arguments": {}})
    error = client.expect_error(req_id)
    assert error["code"] == -32602
