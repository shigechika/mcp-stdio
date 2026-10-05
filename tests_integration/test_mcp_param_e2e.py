"""#459: x-mcp-header -> Mcp-Param-{Name} against a real python-sdk v2 server.

python-sdk v2 validates `Mcp-Param-*` before dispatch on every modern-era
`tools/call` and rejects a missing header with `-32020 HeaderMismatch`. The
reference server's `region_op` annotates `region` with
`x-mcp-header: Region`, so these scenarios exercise the real enforcement,
not a mock of it.
"""

from __future__ import annotations

CALL = {"name": "region_op", "arguments": {"region": "us-west1"}}


def test_the_server_rejects_a_call_without_the_header(harness_server, relay_factory):
    """The premise: with mirroring off, the same call fails upstream."""
    client = relay_factory(
        harness_server.port, extra_args=["--mcp-param-headers", "off"]
    )
    client.initialize()
    client.request("tools/list")
    call_id = client.send_request("tools/call", CALL)
    error = client.expect_error(call_id, timeout=10.0)
    assert "400" in error["message"]


def test_a_listed_tool_is_called_with_its_header(harness_server, relay_factory):
    client = relay_factory(harness_server.port)
    client.initialize()
    tools = client.request("tools/list")
    region_op = next(t for t in tools["tools"] if t["name"] == "region_op")
    assert region_op["inputSchema"]["properties"]["region"]["x-mcp-header"] == "Region"
    result = client.request("tools/call", CALL)
    assert result["content"][0]["text"] == "region us-west1"


def test_a_cold_call_recovers_by_relisting(harness_server, relay_factory):
    """No tools/list first: the call is rejected with -32020, the relay
    re-lists on its own and retries once, and the client sees one result."""
    client = relay_factory(harness_server.port)
    client.initialize()
    result = client.request("tools/call", CALL)
    assert result["content"][0]["text"] == "region us-west1"
    assert client.stderr.contains("re-listing tools")
