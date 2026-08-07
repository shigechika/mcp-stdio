"""A tiny stdio MCP-ish backend used by test_server.py.

Reads newline-delimited JSON-RPC from stdin and reacts:

- ``initialize`` (request)      -> an InitializeResult with protocolVersion
- ``echo`` (request)            -> result {"echoed": <params>, "pid": <os pid>}
- ``slow_echo`` (request)       -> like ``echo``, after a sleep (default 0.3s,
  override with params {"delay": <seconds>}); lets a test keep the request in
  flight long enough to send a duplicate-id retry. Its result also carries
  ``calls`` (a per-process invocation counter) so a test can prove exactly how
  many copies of the request reached the backend.
- ``noreply`` (request)         -> never responds (drives the timeout path)
- ``trigger_push`` (notification) -> emits a server-initiated notification
- ``resources/subscribe`` / ``resources/unsubscribe`` (request) -> the legacy
  empty result, and RECORDED (see ``subscribe_log``)
- ``subscribe_log`` (request)   -> the recorded subscribe/unsubscribe calls, in
  order. #381's refcount tests assert on THIS — wire evidence that a call did
  or did not reach the child — rather than on the absence of updates, which
  passes just as happily when the whole feature is broken.
- ``trigger_resource_update`` (notification) -> emits
  ``notifications/resources/updated`` for ``params.uri``
- ``exit`` (any)                -> the process exits

``--no-resource-subscribe`` in argv drops ``resources.subscribe`` from the
advertised capabilities, so a test can drive serve's capability gate with a
child that genuinely lacks the feature rather than by monkeypatching serve.

``--echo-env VAR`` reads ``os.environ.get(VAR)`` ONCE at process start (the
value a real ``--user-env`` backend would see) and stamps it into the
``initialize`` response's ``serverInfo`` as ``envValue``, so a test can prove
what a spawned child actually saw in its environment without adding a whole
new request method.

Run as: ``python -m tests._fake_backend`` is not needed — it is launched as a
script path by the tests.
"""

import json
import os
import sys
import time

# Off by default would make every existing caller opt IN to the common case;
# the flag instead removes the capability, so the fake child looks like a
# normal modern-capable server unless a test says otherwise.
_ADVERTISES_RESOURCE_SUBSCRIBE = "--no-resource-subscribe" not in sys.argv

# Read once at spawn time -- exactly what a --user-env-aware backend would do,
# and what makes this a meaningful probe of the env a specific child process
# was actually started with (as opposed to one read live, which could not
# distinguish "the gateway injected nothing" from "this test forgot to ask").
_ECHO_ENV_VALUE: str | None = None
if "--echo-env" in sys.argv:
    _idx = sys.argv.index("--echo-env")
    if _idx + 1 < len(sys.argv):
        _ECHO_ENV_VALUE = os.environ.get(sys.argv[_idx + 1])


FAKE_TOOLS = [
    {
        "name": "echo_tool",
        "description": "Echo the arguments back.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
    }
]


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    slow_echo_calls = 0
    # Every `resources/subscribe` / `resources/unsubscribe` this child has
    # received, in order, as (method, uri) pairs. #381's refcount lifecycle
    # is asserted against this log.
    subscribe_log: list[list[str]] = []
    while True:
        line = sys.stdin.readline()
        if line == "":
            break  # EOF
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        mid = msg.get("id")
        if method == "initialize" and "id" in msg:
            server_info = {"name": "fake", "version": "0"}
            if "--echo-env" in sys.argv:
                server_info["envValue"] = _ECHO_ENV_VALUE
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "serverInfo": server_info,
                        "capabilities": (
                            {"resources": {"subscribe": True}}
                            if _ADVERTISES_RESOURCE_SUBSCRIBE
                            else {}
                        ),
                    },
                }
            )
        elif method == "echo" and "id" in msg:
            # pid lets a test prove two sessions hit two distinct child
            # processes (no cross-session response leakage).
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {"echoed": msg.get("params"), "pid": os.getpid()},
                }
            )
        elif method == "slow_echo" and "id" in msg:
            slow_echo_calls += 1
            params = msg.get("params") or {}
            time.sleep(params.get("delay", 0.3))
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "echoed": msg.get("params"),
                        "pid": os.getpid(),
                        "calls": slow_echo_calls,
                    },
                }
            )
        elif method == "tools/list" and "id" in msg:
            # #270 Phase 3 P3-B: the modern dispatch path stamps caching
            # hints onto `tools/list`, so the unit suite needs a child
            # that actually answers it. Shape mirrors
            # tests_integration/_legacy_child.py's TOOLS.
            _send({"jsonrpc": "2.0", "id": mid, "result": {"tools": FAKE_TOOLS}})
        elif method == "tools/call" and "id" in msg:
            params = msg.get("params") or {}
            if params.get("name") != "echo_tool":
                _send(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {"code": -32602, "message": "unknown tool"},
                    }
                )
            else:
                _send(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(
                                        params.get("arguments") or {}, sort_keys=True
                                    ),
                                }
                            ],
                            "isError": False,
                        },
                    }
                )
        elif method == "ask_client" and "id" in msg:
            # Emits a child-INITIATED request, which a gateway-owned child
            # must never be able to hang on (P3-B reject arm).
            _send({"jsonrpc": "2.0", "id": "child-1", "method": "elicitation/create"})
            _send({"jsonrpc": "2.0", "id": mid, "result": {"asked": True}})
        elif method == "noreply" and "id" in msg:
            pass  # intentionally silent -> exercises the gateway timeout path
        elif method == "trigger_push":  # a notification (no id)
            _send(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {"hello": "world"},
                }
            )
        elif method in ("resources/subscribe", "resources/unsubscribe") and "id" in msg:
            # The legacy wire shape: an EMPTY result, carrying no per-URI
            # confirmation of any kind — which is exactly why serve drives
            # these fire-and-forget rather than blocking its ack on them.
            subscribe_log.append([method, (msg.get("params") or {}).get("uri")])
            _send({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif method == "subscribe_log" and "id" in msg:
            _send({"jsonrpc": "2.0", "id": mid, "result": {"calls": subscribe_log}})
        elif method == "trigger_resource_update":  # a notification (no id)
            _send(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/resources/updated",
                    "params": {"uri": (msg.get("params") or {}).get("uri")},
                }
            )
        elif method == "trigger_list_changed":  # a notification (no id)
            # #374: drive the listChanged trio on demand. `params.family`
            # picks which one, so one arm covers the filter-suppression
            # tests too (ask for tools, fire prompts, expect silence).
            family = (msg.get("params") or {}).get("family", "tools")
            _send(
                {
                    "jsonrpc": "2.0",
                    "method": f"notifications/{family}/list_changed",
                    "params": {"from": family},
                }
            )
        elif method == "exit":
            sys.exit(0)
        elif "id" in msg:
            # #270 Phase 3 P3-B: any OTHER request gets method-not-found
            # rather than silence. Once serve dispatches modern requests
            # here, a silent child means the handler blocks for the full
            # 120 s backend timeout — a hang indistinguishable from a
            # gateway bug. (`noreply` above stays silent on purpose: that
            # IS the timeout path, and it is opt-in by name.)
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                }
            )
        # any other notification: ignore


if __name__ == "__main__":
    main()
