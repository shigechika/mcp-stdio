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
- ``exit`` (any)                -> the process exits

Run as: ``python -m tests._fake_backend`` is not needed — it is launched as a
script path by the tests.
"""

import json
import os
import sys
import time


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
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "serverInfo": {"name": "fake", "version": "0"},
                        "capabilities": {},
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
        elif method == "exit":
            sys.exit(0)
        # any other notification: ignore


if __name__ == "__main__":
    main()
